import iam = require('aws-cdk-lib/aws-iam');
import kms = require('aws-cdk-lib/aws-kms');
import lambda = require('aws-cdk-lib/aws-lambda');
import cdk = require('aws-cdk-lib');
import path = require('path');
import {Construct} from "constructs";
import {Effect} from "aws-cdk-lib/aws-iam";
import {Conditions} from "aws-cdk-lib/aws-iam/lib/policy-statement";

const resourceType = 'Custom::EC2-Key-Pair';
const ID = `CFN::Resource::${resourceType}`;
const createdByTag = 'CreatedByCfnCustomResource';
const cleanID = ID.replace(/:+/g, '-');
const lambdaTimeout = 3; // minutes

/**
 * Definition of EC2 Key Pair
 */
export interface KeyPairProps extends cdk.ResourceProps {
  /**
   * Name of the Key Pair
   *
   * In AWS Secrets Manager the key will be prefixed with `ec2-ssh-key/`.
   *
   * The name can be up to 255 characters long. Valid characters include _, -, a-z, A-Z, and 0-9.
   */
  readonly name: string;

  /**
   * The description for the key in AWS Secrets Manager
   * @default - ''
   */
  readonly description?: string;

  /**
   * The KMS key used to encrypt the Secrets Manager secrets with
   *
   * This needs to be a key created in the same stack. You cannot use a key imported via ARN, because the keys access policy will need to be modified.
   *
   * @default - `alias/aws/secretsmanager`
   */
  readonly kms?: kms.Key;

  /**
   * The KMS key to use to encrypt the private key with
   *
   * This needs to be a key created in the same stack. You cannot use a key imported via ARN, because the keys access policy will need to be modified.
   *
   * If no value is provided, the property `kms` will be used instead.
   *
   * @default - `this.kms`
   */
  readonly kmsPrivateKey?: kms.Key;

  /**
   * The KMS key to use to encrypt the public key with
   *
   * This needs to be a key created in the same stack. You cannot use a key imported via ARN, because the keys access policy will need to be modified.
   *
   * If no value is provided, the property `kms` will be used instead.
   *
   * @default - `this.kms`
   */
  readonly kmsPublicKey?: kms.Key;

  /**
   * Store the public key as a secret
   *
   * @default - false
   */
  readonly storePublicKey?: boolean;

  /**
   * Expose the public key as property `publicKeyValue`
   *
   * @default - false
   */
  readonly exposePublicKey?: boolean;

  /**
   * When the resource is destroyed, after how many days the private and public key in the AWS Secrets Manager should be deleted.
   *
   * Valid values are 0 and 7 to 30
   *
   * @default 0
   */
  readonly removeKeySecretsAfterDays?: number;

  /**
   * Prefix for the secret in AWS Secrets Manager.
   *
   * @default `ec2-ssh-key/`
   */
  readonly secretPrefix?: string;

  /**
   * A prefix for all resource names.
   *
   * By default all resources are prefixed with the stack name to avoid collisions with other stacks. This might cause problems when you work with long stack names and can be overridden through this parameter.
   *
   * @default Name of the stack
   */
  readonly resourcePrefix?: string;
}

/**
 * An EC2 Key Pair
 */
export class KeyPair extends Construct implements cdk.ITaggable {
  /**
   * The lambda function that is created
   */
  public readonly lambda: lambda.IFunction;

  /**
   * ARN of the private key in AWS Secrets Manager
   */
  public readonly privateKeyArn: string = '';

  /**
   * ARN of the public key in AWS Secrets Manager
   */
  public readonly publicKeyArn: string = '';

  /**
   * The public key.
   *
   * Only filled, when `exposePublicKey = true`
   */
  public readonly publicKeyValue: string = '';

  /**
   * Name of the Key Pair
   */
  public readonly keyPairName: string = '';

  /**
   * ID of the Key Pair
   */
  public readonly keyPairID: string = '';

  /**
   * Resource tags
   */
  public readonly tags: cdk.TagManager;

  public readonly prefix: string = '';

  /**
   * Defines a new EC2 Key Pair. The private key will be stored in AWS Secrets Manager
   */
  constructor(scope: Construct, id: string, props: KeyPairProps) {
    super(scope, id);

    if (
      props.removeKeySecretsAfterDays &&
      (props.removeKeySecretsAfterDays < 0 ||
        (props.removeKeySecretsAfterDays > 0 &&
          props.removeKeySecretsAfterDays < 7) ||
        props.removeKeySecretsAfterDays > 30)
    ) {
      cdk.Annotations.of(this).addError(
        `Parameter removeKeySecretsAfterDays must be 0 or between 7 and 30. Got ${props.removeKeySecretsAfterDays}`
      );
    }

    const stack = cdk.Stack.of(this).stackName;
    this.prefix = props.resourcePrefix || stack;
    if (this.prefix.length + cleanID.length > 62)
      // Cloudformation limits names to 63 characters.
      cdk.Annotations.of(this).addError(
        `Cloudformation limits names to 63 characters.
         Prefix ${this.prefix} is too long to be used as a prefix for your roleName. Define parameter resourcePrefix?:`
      );
    this.lambda = this.ensureLambda();

    this.tags = new cdk.TagManager(cdk.TagType.MAP, 'Custom::EC2-Key-Pair');
    this.tags.setTag(createdByTag, ID);

    const kmsPrivate = props.kmsPrivateKey || props.kms;
    const kmsPublic = props.kmsPublicKey || props.kms;

    const key = new cdk.CustomResource(this, `EC2-Key-Pair-${props.name}`, {
      serviceToken: this.lambda.functionArn,
      resourceType: resourceType,
      properties: {
        Name: props.name,
        Description: props.description || '',
        KmsPrivate: kmsPrivate?.keyArn || 'alias/aws/secretsmanager',
        KmsPublic: kmsPublic?.keyArn || 'alias/aws/secretsmanager',
        StorePublicKey: props.storePublicKey || false,
        ExposePublicKey: props.exposePublicKey || false,
        RemoveKeySecretsAfterDays: props.removeKeySecretsAfterDays || 0,
        SecretPrefix: props.secretPrefix || 'ec2-ssh-key/',
        StackName: stack,
        Tags: cdk.Lazy.any({
          produce: () => this.tags.renderTags(),
        }),
      },
    });

    if (typeof props.kms !== 'undefined') {
      props.kms.grantEncryptDecrypt(this.lambda.role!);
      key.node.addDependency(props.kms);
      key.node.addDependency(this.lambda.role!);
    }

    if (typeof props.kmsPrivateKey !== 'undefined') {
      props.kmsPrivateKey.grantEncryptDecrypt(this.lambda.role!);
      key.node.addDependency(props.kmsPrivateKey);
      key.node.addDependency(this.lambda.role!);
    }

    if (typeof props.kmsPublicKey !== 'undefined') {
      props.kmsPublicKey.grantEncryptDecrypt(this.lambda.role!);
      key.node.addDependency(props.kmsPublicKey);
      key.node.addDependency(this.lambda.role!);
    }

    this.privateKeyArn = key.getAttString('PrivateKeyARN');
    this.publicKeyArn = key.getAttString('PublicKeyARN');
    this.publicKeyValue = key.getAttString('PublicKeyValue');
    this.keyPairName = key.getAttString('KeyPairName');
    this.keyPairID = key.getAttString('KeyPairID');
  }

  private ensureLambda(): lambda.Function {
    const stack = cdk.Stack.of(this);
    const constructName = 'EC2-Key-Name-Manager-Lambda';
    const existing = stack.node.tryFindChild(constructName);
    if (existing) {
      return existing as lambda.Function;
    }

    const statementDescribeKeys = new iam.PolicyStatement({
        actions: ["ec2:DescribeKeyPairs"],
        effect:Effect.ALLOW
    });

    const statementCreationCreatedByTag = new iam.PolicyStatement({
        actions: ["ec2:CreateKeyPair","ec2:CreateTags"],
        effect:Effect.ALLOW,
        resources: [`arn:${ stack.partition || 'aws' }:ec2:*:*:key-pair/*`]
    });
    const statementCreationCreatedByTagCondition:Conditions = {};
    statementCreationCreatedByTagCondition[`ec2:aws:RequestTag/${createdByTag}`] = ID;
    statementCreationCreatedByTag.addConditions({ "StringLike": statementCreationCreatedByTagCondition });

    const statementDeleteUpdateCreatedByTag = new iam.PolicyStatement({
        actions: ["ec2:CreateKeyPair","ec2:DeleteKeyPair","ec2:CreateTags","ec2:DeleteTags"],
        effect:Effect.ALLOW,
        resources: [`arn:${ stack.partition || 'aws' }:ec2:*:*:key-pair/*`]
    });
    const statementDeleteUpdateCreatedByTagCondition:Conditions = {};
    statementDeleteUpdateCreatedByTagCondition[`ec2:aws:ResourceTag/${createdByTag}`] = ID;
    statementDeleteUpdateCreatedByTag.addConditions({ "StringLike": statementDeleteUpdateCreatedByTagCondition });


      const statementListSecrets = new iam.PolicyStatement({
          actions: ["secretsmanager:ListSecrets"],
          effect: Effect.ALLOW
      });


      const statementCreationSecrets = new iam.PolicyStatement({
          actions: ["secretsmanager:CreateSecret","secretsmanager:TagResource"],
          effect:Effect.ALLOW,
      });
      const statementCreationSecretsRequestTagCondition:Conditions = {};
      statementCreationSecretsRequestTagCondition[`secretsmanager:aws:RequestTag/${createdByTag}`] = ID;
      statementCreationSecrets.addConditions({ "StringLike": statementCreationSecretsRequestTagCondition });

      const statementDeleteUpdateSecrets = new iam.PolicyStatement({
          actions: ["secretsmanager:GetSecretValue","secretsmanager:GetResourcePolicy",
              "secretsmanager:RestoreSecret", "secretsmanager:ListSecretVersionIds",
              "secretsmanager:UntagResource", "secretsmanager:DescribeSecret", "secretsmanager:DeleteResourcePolicy"
              , "secretsmanager:PutSecretValue", "secretsmanager:PutResourcePolicy",
              "secretsmanager:UpdateSecret", "secretsmanager:UpdateSecretVersionStage"],
          effect:Effect.ALLOW,
      });
      const statementDeleteUpdateSecretsCondition:Conditions = {};
      statementDeleteUpdateSecretsCondition[`secretsmanager:aws:RequestTag/${createdByTag}`] = ID;
      statementDeleteUpdateSecrets.addConditions({ "StringLike": statementDeleteUpdateSecretsCondition });



      const policy = new iam.ManagedPolicy(stack, 'EC2-Key-Pair-Manager-Policy', {
      managedPolicyName: `${this.prefix}-${cleanID}`,
      description: `Used by Lambda ${cleanID}, which is a custom CFN resource, managing EC2 Key Pairs`,
      statements: [ statementDescribeKeys, statementCreationCreatedByTag, statementDeleteUpdateCreatedByTag,
          statementListSecrets, statementCreationSecrets, statementDeleteUpdateSecrets ],
    });

    const role = new iam.Role(stack, 'EC2-Key-Pair-Manager-Role', {
      roleName: `${this.prefix}-${cleanID}`,
      description: `Used by Lambda ${cleanID}, which is a custom CFN resource, managing EC2 Key Pairs`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        policy,
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSLambdaBasicExecutionRole'
        ),
      ],
    });

    const fn = new lambda.Function(stack, constructName, {
      functionName: `${this.prefix}-${cleanID}`,
      role: role,
      description: 'Custom CFN resource: Manage EC2 Key Pairs',
      runtime: lambda.Runtime.NODEJS_14_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '../lambda/code.zip')),
      timeout: cdk.Duration.minutes(lambdaTimeout),
    });

    return fn;
  }

  /**
   * Grants read access to the private key in AWS Secrets Manager
   */
  grantReadOnPrivateKey(grantee: iam.IGrantable) {
    return this.grantRead(this.privateKeyArn, grantee);
  }

  /**
   * Grants read access to the public key in AWS Secrets Manager
   */
  grantReadOnPublicKey(grantee: iam.IGrantable) {
    return this.grantRead(this.publicKeyArn, grantee);
  }

  private grantRead(arn: string, grantee: iam.IGrantable) {
    const result = iam.Grant.addToPrincipal({
      grantee,
      actions: [
        'secretsmanager:DescribeSecret',
        'secretsmanager:GetResourcePolicy',
        'secretsmanager:GetSecretValue',
        'secretsmanager:ListSecretVersionIds',
      ],
      resourceArns: [arn],
      scope: this,
    });
    return result;
  }
}
