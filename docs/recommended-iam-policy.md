# Recommended AWS IAM policy

For individuals comfortable applying [custom IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html) in AWS, we recommend using the below IAM policy instead of `AmazonEC2FullAccess` when creating the AWS role for Patrolaroid. 

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1622650196578",
      "Action": [
        "ec2:AttachVolume",
        "ec2:CreateSnapshot",
        "ec2:CreateVolume",
        "ec2:DeleteVolume",
        "ec2:DescribeSnapshots",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
```

Thanks to @Jonty for the suggestion.
