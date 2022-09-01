# Centralize SecurityHub

Installing this Customization will enable Security Hub in all Control Tower managed accounts, with the SecOps account acting as the default Security Hub Master.

It can also be run in non-Control Tower managed Organizations, if the SecurityHub Region Filter and All OU Filters are selected during deployment.

This is done by deploying a SecurityHub Enabler lambda function in the master account. It runs periodically and checks each Control Tower managed account/region to ensure that they have been invited into the master SecurityHub account and that SecurityHub is enabled.  It is also triggered by Control Tower Lifecycle events to ensure there is minimal delay between new accounts being created and Security Hub being enabled in them.

![Logical Flow](docs/images/SecurityHub.png)

### Attributions

This repository has been forked from [aws-samples](https://github.com/aws-samples/aws-control-tower-securityhub-enabler)
The original code for automating SecurityHub enablement in AWS accounts is present [here](https://github.com/awslabs/aws-securityhub-multiaccount-scripts). This has been extended to work with Control Tower.

The cfnResponse module has recently been impacted by [removal of the vendored version of requests from botocore](https://aws.amazon.com/blogs/developer/removing-the-vendored-version-of-requests-from-botocore/), so the send function has been directly imported from [here](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html).

## Instructions

1. Run src/package.sh to package the code and dependencies
1. Upload the src/securityhub_enabler.zip file to an S3 bucket, note the bucket name (`security-hub-enabler`)
1. Gather other information for deployment parameters:

    - In AWS Organizations, look on the Settings page for the Organization ID.  It will be o-xxxxxxxxxx
    - In AWS Organizations, look on the Accounts page for the SecOps account ID.

1. Launch the CloudFormation stack using the `aws-control-tower-securityhub-enabler.template` file as the source.  The values noted in the steps above will be entered as parameters to the CloudFormation stack.  
