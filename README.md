# Important Update

As of Nov 23, 2020, AWS Security Hub integrates with AWS Organzations and that integration is a less complex way to enable Security Hub for your Control Tower environment than this automation.  Please review it [here](https://aws.amazon.com/about-aws/whats-new/2020/11/aws-security-hub-integrates-with-aws-organizations-for-simplified-security-posture-management/) and see if it meets your needs before investing in the effort to deploy this. 

# Centralize SecurityHub

Installing this Customization will enable Security Hub in all Control Tower managed accounts, with the Audit account acting as the default Security Hub Master.

This is done by deploying a SecurityHub Enabler lambda function in the master account. It runs periodically and checks each Control Tower managed account/region to ensure that they have been invited into the master SecurityHub account and that SecurityHub is enabled.  It is also triggered by Control Tower Lifecycle events to ensure there is minimal delay between new accounts being created and Security Hub being enabled in them.

![Logical Flow](docs/images/SecurityHub.png)

### Attributions

The original code for automating SecurityHub enablement in AWS accounts is present [here](https://github.com/awslabs/aws-securityhub-multiaccount-scripts). This has been extended to work with Control Tower.

The cfnResponse module has recently been impacted by [removal of the vendored version of requests from botocore](https://aws.amazon.com/blogs/developer/removing-the-vendored-version-of-requests-from-botocore/), so the send function has been directly imported from [here](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html).

## Instructions

1. Upload the src/securityhub_enabler.zip file to an S3 bucket, note the bucket name
1. Gather other information for deployment parameters:

    - In AWS Organizations, look on the Settings page for the Organization ID.  It will be o-xxxxxxxxxx
    - In AWS Organizations, look on the Accounts page for the Audit account ID.

1. Launch the CloudFormation stack using the aws-control-tower-securityhub-enabler.template file as the source.  The values noted in the steps above will be entered as parameters to the CloudFormation stack.  
