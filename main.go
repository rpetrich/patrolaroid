package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	yara "github.com/capsule8/go-yara"
)

func run() int {
	// load the AWS config
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load AWS config: %v", err)
	}
	// connect to local instance metadata service
	metadataService := imds.NewFromConfig(cfg)
	metadataResponse, err := metadataService.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "placement/availability-zone",
	})
	if err != nil {
		log.Fatalf("failed to lookup availability zone instance metadata: %v", err)
	}
	azBytes, err := ioutil.ReadAll(metadataResponse.Content)
	if err != nil {
		log.Fatalf("failed to read availability zone content: %v", err)
	}
	az := string(azBytes)
	cfg, err = config.LoadDefaultConfig(ctx,
		config.WithRegion(az[:len(az)-1]),
	)
	if err != nil {
		log.Fatalf("unable to reload AWS config: %v", err)
	}
	metadataResponse, err = metadataService.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "instance-id",
	})
	if err != nil {
		log.Fatalf("failed to lookup instance id instance metadata: %v", err)
	}
	instanceIdBytes, err := ioutil.ReadAll(metadataResponse.Content)
	if err != nil {
		log.Fatalf("failed to read instance id content: %v", err)
	}
	instanceId := string(instanceIdBytes)
	// parse arguments
	signaturePathFlag := flag.String("signatures", "./signatures", "a path to YARA signatures")
	volumeIdsFlag := flag.String("volume-ids", "", "a comma separated list of volume IDs to scan")
	flag.Parse()
	// load YARA
	compiler, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Could not initialize yara compiler: %v", err)
	}
	defer compiler.Destroy()
	// read rules from filesystem
	ruleCount := 0
	err = filepath.Walk(*signaturePathFlag, func(recursivePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := filepath.Ext(recursivePath)
		if ext != ".yar" && ext != ".yara" {
			return nil
		}
		log.Printf("loading yara rule from %q", recursivePath)
		f, err := os.Open(recursivePath)
		if err != nil {
			return fmt.Errorf("error opening yara signature from %q: %v", recursivePath, err)
		}
		defer f.Close()
		err = compiler.AddFile(f, recursivePath)
		if err != nil {
			log.Printf("error compiling yara signature from %q: %v", recursivePath, err)
		} else {
			ruleCount++
		}
		return nil
	})
	if err != nil {
		log.Fatalf("could not initialize yara rules: %v", err)
	}
	// compile the rules
	r, err := compiler.GetRules()
	if err != nil {
		log.Fatalf("failed to compile yara rules: %s", err)
	}
	defer r.Destroy()
	if ruleCount == 0 {
		log.Fatalf("no rules to scan files with; place signatures in ./signatures/*.yar")
	}
	// connect to EC2
	client := ec2.NewFromConfig(cfg)
	dryRun := false
	// search for volumes
	var volumeIds []string
	if *volumeIdsFlag != "" {
		volumeIds = strings.Split(*volumeIdsFlag, ",")
	} else {
		var nextToken *string
		for {
			volumes, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
				DryRun:    &dryRun,
				NextToken: nextToken,
			})
			if err != nil {
				log.Fatalf("describe volumes request failed: %v", err)
			}
			for _, volume := range volumes.Volumes {
				volumeIds = append(volumeIds, *volume.VolumeId)
				log.Printf("found volume %s", *volume.VolumeId)
			}
			if nextToken = volumes.NextToken; nextToken == nil {
				break
			}
		}
	}
	exitCode := 0
	for _, volumeId := range volumeIds {
		if err = processVolume(ctx, client, az, instanceId, volumeId, r); err != nil {
			log.Printf("%v", err)
			exitCode = 1
		}
	}
	return exitCode
}

func processVolume(ctx context.Context, client *ec2.Client, az string, instanceId string, volumeId string, rules *yara.Rules) error {
	// create a snapshot
	dryRun := false
	log.Printf("creating new snapshot for %q", volumeId)
	description := "Patrolaroid temporary snapshot of " + volumeId
	snapshot, err := client.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
		VolumeId:    &volumeId,
		Description: &description,
		DryRun:      &dryRun,
	})
	if err != nil {
		return fmt.Errorf("create snapshot request failed: %v", err)
	}
	snapshotId := *snapshot.SnapshotId
	log.Printf("created snapshot: %s", snapshotId)
	// create a volume for the snapshot
	snapshotIdKey := "snapshot-id"
	fiveSnapshots := int32(5)
wait_for_snapshot_completion:
	for {
		log.Printf("describing snapshot %q", snapshotId)
		descriptions, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			DryRun: &dryRun,
			Filters: []types.Filter{
				types.Filter{
					Name:   &snapshotIdKey,
					Values: []string{snapshotId},
				},
			},
			MaxResults: &fiveSnapshots,
		})
		if err != nil {
			return fmt.Errorf("unable to query snapshots: %v", err)
		}
		for _, snapshot := range descriptions.Snapshots {
			switch snapshot.State {
			case types.SnapshotStateError:
				if snapshot.StateMessage != nil {
					return fmt.Errorf("creating snapshot failed: %s", *snapshot.StateMessage)
				} else {
					return fmt.Errorf("creating snapshot failed without message")
				}
			case types.SnapshotStateCompleted:
				log.Printf("snapshot completed")
				break wait_for_snapshot_completion
			case types.SnapshotStatePending:
				if snapshot.Progress != nil {
					return fmt.Errorf("snapshot progress: %s", *snapshot.Progress)
				}
			}
		}
		time.Sleep(10 * time.Second)
	}
	createVolumeResponse, err := client.CreateVolume(ctx, &ec2.CreateVolumeInput{
		AvailabilityZone: &az,
		SnapshotId:       &snapshotId,
	})
	if err != nil {
		return fmt.Errorf("create volume request failed: %v", err)
	}
	snapshotVolumeId := *createVolumeResponse.VolumeId
	log.Printf("created snapshot volume: %s", snapshotVolumeId)
	// wait for the volume to become ready
	var attached bool
wait_for_volume_completion:
	for {
		log.Printf("describing snapshot volume %q", snapshotVolumeId)
		fiveVolumes := int32(5)
		volumeIdKey := "volume-id"
		descriptions, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			DryRun: &dryRun,
			Filters: []types.Filter{
				types.Filter{
					Name:   &volumeIdKey,
					Values: []string{snapshotVolumeId},
				},
			},
			MaxResults: &fiveVolumes,
		})
		if err != nil {
			return fmt.Errorf("unable to query volumes: %v", err)
		}
		if len(descriptions.Volumes) == 0 {
			return fmt.Errorf("invalid volume id: %q", volumeId)
		}
		for _, volume := range descriptions.Volumes {
			switch volume.State {
			case types.VolumeStateCreating:
				log.Printf("still creating volume")
			case types.VolumeStateAvailable:
				log.Printf("volume available")
				attached = false
				break wait_for_volume_completion
			case types.VolumeStateInUse:
				log.Printf("volume is in use, assuming it was just attached")
				attached = true
				break wait_for_volume_completion
			case types.VolumeStateDeleting:
				return fmt.Errorf("volume is being deleted")
			case types.VolumeStateDeleted:
				return fmt.Errorf("volume is deleted")
			case types.VolumeStateError:
				return fmt.Errorf("volume is in error state")
			}
		}
		time.Sleep(10 * time.Second)
	}
	// attach the volume
	device := "/dev/sda2"
	if !attached {
		_, err = client.AttachVolume(ctx, &ec2.AttachVolumeInput{
			InstanceId: &instanceId,
			VolumeId:   &snapshotVolumeId,
			Device:     &device,
		})
		if err != nil {
			return fmt.Errorf("attach volume request failed: %v", err)
		}
	wait_for_volume_attachment:
		for {
			log.Printf("describing volume %q", snapshotVolumeId)
			fiveVolumes := int32(5)
			volumeIdKey := "volume-id"
			descriptions, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
				DryRun: &dryRun,
				Filters: []types.Filter{
					types.Filter{
						Name:   &volumeIdKey,
						Values: []string{snapshotVolumeId},
					},
				},
				MaxResults: &fiveVolumes,
			})
			if err != nil {
				return fmt.Errorf("unable to query volumes: %v", err)
			}
			for _, volume := range descriptions.Volumes {
				for _, attachment := range volume.Attachments {
					if *attachment.InstanceId == instanceId {
						switch attachment.State {
						case types.VolumeAttachmentStateAttaching:
							log.Printf("volume is attaching")
						case types.VolumeAttachmentStateAttached:
							log.Printf("volume is attached")
							break wait_for_volume_attachment
						case types.VolumeAttachmentStateDetaching:
							log.Printf("volume is detaching")
						case types.VolumeAttachmentStateDetached:
							return fmt.Errorf("volume is detached, but expected it to be in another state")
						case types.VolumeAttachmentStateBusy:
							return fmt.Errorf("volume is busy, but expected it to be in another state")
						}
					}
				}
			}
			time.Sleep(5 * time.Second)
		}
	}
	// find the newest nvme devices
	files, err := ioutil.ReadDir("/dev")
	if err != nil {
		return fmt.Errorf("unable to read local devices: %v", err)
	}
	var newestDevice string
	for _, file := range files {
		if fileName := file.Name(); strings.HasPrefix(fileName, "nvme") {
			newestDevice = "/dev/" + fileName
		}
	}
	if newestDevice == "" {
		return fmt.Errorf("unable to find any nvme devices")
	}
	log.Printf("latest device is %s", newestDevice)
	// mount the device
	_ = os.Mkdir("./snapshot", 0644)
	err = syscall.Mount(newestDevice, "./snapshot", "ext4", syscall.MS_RDONLY|syscall.MS_NOEXEC, "")
	if err != nil {
		return fmt.Errorf("failed to mount device: %v", err)
	}
	log.Printf("mounted successfully")
	// scan the mount
	err = filepath.Walk("./snapshot", func(recursivePath string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Precheck to make sure we're dealing with an actual file
		if info.IsDir() || info.Size() == 0 {
			return nil
		}
		if info.Mode()&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket|os.ModeCharDevice|os.ModeSymlink) != 0 {
			return nil
		}
		// Actually scan the file
		var m yara.MatchRules
		err = rules.ScanFile(recursivePath, 0, 0, &m)
		if err != nil {
			errorText := err.Error()
			// Ignore bad symlinks and unlink race conditions. Have to
			// compare by string since go-yara doesn't use structured error
			// types :(
			if errorText != "could not open file" && errorText != "could not map file" {
				log.Printf("could not scan %q: %v", recursivePath, err)
			}
			return nil
		}
		// If we have matches, dispatch an alert
		if len(m) != 0 {
			log.Printf("file in volume %s at path %q violated rule %q from %q", volumeId, strings.TrimPrefix(recursivePath, "snapshot"), m[0].Rule, m[0].Namespace)
		}
		return nil
	})
	if err != nil {
		log.Printf("error scanning: %v", err)
	}
	log.Printf("finished scanning, unmounting")
	// unmount the volume
	syscall.Unmount("./snapshot", 0)
	time.Sleep(1 * time.Second)
	log.Printf("finished unmounting, detaching")
	// detach the snapshot volume
	_, err = client.DetachVolume(ctx, &ec2.DetachVolumeInput{
		InstanceId: &instanceId,
		VolumeId:   &snapshotVolumeId,
	})
	if err != nil {
		return fmt.Errorf("detach volume request failed: %v", err)
	}
wait_for_volume_detachment:
	for {
		log.Printf("describing volume %q", snapshotVolumeId)
		fiveVolumes := int32(5)
		volumeIdKey := "volume-id"
		descriptions, err := client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{
			DryRun: &dryRun,
			Filters: []types.Filter{
				types.Filter{
					Name:   &volumeIdKey,
					Values: []string{snapshotVolumeId},
				},
			},
			MaxResults: &fiveVolumes,
		})
		if err != nil {
			return fmt.Errorf("unable to query volumes: %v", err)
		}
		for _, volume := range descriptions.Volumes {
			switch volume.State {
			case types.VolumeStateCreating:
				log.Printf("still creating volume")
			case types.VolumeStateAvailable:
				log.Printf("volume available")
				break wait_for_volume_detachment
			case types.VolumeStateInUse:
				log.Printf("volume is in use, waiting for detachment")
			case types.VolumeStateDeleting:
				log.Printf("volume is being deleted")
			case types.VolumeStateDeleted:
				return nil
			case types.VolumeStateError:
				return fmt.Errorf("volume is in error state")
			}
		}
		time.Sleep(10 * time.Second)
	}
	log.Printf("finished detaching, deleting volume")
	// delete the snapshot volume
	_, err = client.DeleteVolume(ctx, &ec2.DeleteVolumeInput{
		VolumeId: &snapshotVolumeId,
	})
	if err != nil {
		return fmt.Errorf("delete volume request failed: %v", err)
	}
	return nil
}

func main() {
	os.Exit(run())
}
