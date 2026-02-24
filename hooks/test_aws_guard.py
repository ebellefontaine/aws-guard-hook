#!/usr/bin/env python3
"""
Unit tests for aws-guard.py

Run with:  python3 -m pytest hooks/test_aws_guard.py -v
       or: python3 hooks/test_aws_guard.py
"""

import sys
import os
import unittest

# Make the hooks directory importable when running directly.
sys.path.insert(0, os.path.dirname(__file__))

from aws_guard import evaluate_command, is_invocation_allowed, is_s3_cp_download


class TestReadOnlyAllowed(unittest.TestCase):
    """Commands that must pass through."""

    def _allow(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertTrue(allowed, f"Expected ALLOW but got BLOCK for: {cmd!r}  (blocked_inv={blocked!r})")

    # --- describe / list / get ---
    def test_describe_instances(self):
        self._allow("aws ec2 describe-instances")

    def test_describe_with_filters(self):
        self._allow("aws ec2 describe-instances --filters Name=instance-state-name,Values=running")

    def test_list_buckets(self):
        self._allow("aws s3api list-buckets")

    def test_get_object(self):
        self._allow("aws s3api get-object --bucket my-bucket --key path/to/file.txt /tmp/file.txt")

    def test_list_functions(self):
        self._allow("aws lambda list-functions")

    def test_get_function(self):
        self._allow("aws lambda get-function --function-name my-fn")

    def test_describe_stacks(self):
        self._allow("aws cloudformation describe-stacks")

    def test_get_role(self):
        self._allow("aws iam get-role --role-name MyRole")

    def test_list_roles(self):
        self._allow("aws iam list-roles")

    # --- sts always-allowed ---
    def test_sts_get_caller_identity(self):
        self._allow("aws sts get-caller-identity")

    def test_sts_get_caller_identity_with_output(self):
        self._allow("aws sts get-caller-identity --output json")

    # --- configure always-allowed ---
    def test_configure_list(self):
        self._allow("aws configure list")

    def test_configure_get(self):
        self._allow("aws configure get region")

    def test_configure_list_profiles(self):
        self._allow("aws configure list-profiles")

    # --- s3 always-allowed ---
    def test_s3_ls(self):
        self._allow("aws s3 ls")

    def test_s3_ls_bucket(self):
        self._allow("aws s3 ls s3://my-bucket/")

    def test_s3_presign(self):
        self._allow("aws s3 presign s3://my-bucket/object.txt")

    def test_s3_cp_download(self):
        self._allow("aws s3 cp s3://my-bucket/file.txt /tmp/file.txt")

    def test_s3_cp_download_with_flags(self):
        self._allow("aws s3 cp --region us-east-1 s3://my-bucket/file.txt /tmp/file.txt")

    # --- logs always-allowed ---
    def test_logs_tail(self):
        self._allow("aws logs tail /aws/lambda/my-function")

    def test_logs_tail_follow(self):
        self._allow("aws logs tail /aws/lambda/my-function --follow")

    # --- DynamoDB scan ---
    def test_dynamodb_scan(self):
        self._allow("aws dynamodb scan --table-name MyTable")

    def test_dynamodb_batch_get_item(self):
        self._allow("aws dynamodb batch-get-item --request-items file://req.json")

    def test_dynamodb_query(self):
        self._allow("aws dynamodb query --table-name MyTable --key-condition-expression 'pk = :pk'")

    # --- presigned URL generation ---
    def test_generate_presigned_url(self):
        self._allow("aws s3api generate-presigned-url --bucket my-bucket --key file.txt")

    # --- validate ---
    def test_validate_template(self):
        self._allow("aws cloudformation validate-template --template-body file://template.yaml")

    # --- estimate ---
    def test_estimate_template_cost(self):
        self._allow("aws cloudformation estimate-template-cost --template-body file://t.yaml")

    # --- global flags before service ---
    def test_global_region_flag(self):
        self._allow("aws --region us-west-2 ec2 describe-instances")

    def test_global_profile_flag(self):
        self._allow("aws --profile prod ec2 describe-instances")

    # --- pipelines where aws part is read-only ---
    def test_piped_to_jq(self):
        self._allow("aws ec2 describe-instances | jq '.Reservations[].Instances[]'")

    def test_piped_to_grep(self):
        self._allow("aws iam list-roles | grep MyRole")

    # --- command substitution ---
    def test_command_substitution_read(self):
        self._allow('ACCOUNT=$(aws sts get-caller-identity --query Account --output text)')

    def test_backtick_read(self):
        self._allow('ACCOUNT=`aws sts get-caller-identity --query Account --output text`')

    # --- non-AWS commands pass through ---
    def test_non_aws_command(self):
        self._allow("ls -la")

    def test_git_command(self):
        self._allow("git status")

    def test_terraform_apply(self):
        self._allow("terraform apply -auto-approve")

    def test_cdk_deploy(self):
        self._allow("cdk deploy")

    def test_pulumi_up(self):
        self._allow("pulumi up")

    def test_env_var_assignment_then_non_aws(self):
        self._allow("export REGION=us-east-1")


class TestWriteBlocked(unittest.TestCase):
    """Commands that must be blocked."""

    def _block(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertFalse(allowed, f"Expected BLOCK but got ALLOW for: {cmd!r}")

    # --- EC2 mutations ---
    def test_run_instances(self):
        self._block("aws ec2 run-instances --image-id ami-12345678 --instance-type t3.micro")

    def test_terminate_instances(self):
        self._block("aws ec2 terminate-instances --instance-ids i-1234567890abcdef0")

    def test_stop_instances(self):
        self._block("aws ec2 stop-instances --instance-ids i-1234567890abcdef0")

    def test_create_security_group(self):
        self._block("aws ec2 create-security-group --group-name MySG --description test")

    def test_delete_security_group(self):
        self._block("aws ec2 delete-security-group --group-id sg-12345")

    def test_authorize_security_group_ingress(self):
        self._block("aws ec2 authorize-security-group-ingress --group-id sg-12345 --protocol tcp --port 22 --cidr 0.0.0.0/0")

    def test_modify_instance_attribute(self):
        self._block("aws ec2 modify-instance-attribute --instance-id i-abc --attribute instanceType")

    # --- S3 mutations ---
    def test_s3_rm(self):
        self._block("aws s3 rm s3://my-bucket/file.txt")

    def test_s3_mv(self):
        self._block("aws s3 mv s3://src-bucket/file.txt s3://dst-bucket/file.txt")

    def test_s3_sync(self):
        self._block("aws s3 sync ./local-dir s3://my-bucket/")

    def test_s3_mb(self):
        self._block("aws s3 mb s3://new-bucket")

    def test_s3_rb(self):
        self._block("aws s3 rb s3://old-bucket --force")

    def test_s3_cp_upload(self):
        self._block("aws s3 cp /tmp/file.txt s3://my-bucket/file.txt")

    def test_s3_cp_s3_to_s3(self):
        self._block("aws s3 cp s3://src/file.txt s3://dst/file.txt")

    def test_s3api_put_object(self):
        self._block("aws s3api put-object --bucket my-bucket --key file.txt --body file.txt")

    def test_s3api_delete_object(self):
        self._block("aws s3api delete-object --bucket my-bucket --key file.txt")

    def test_s3api_create_bucket(self):
        self._block("aws s3api create-bucket --bucket new-bucket --region us-east-1")

    # --- IAM mutations ---
    def test_create_role(self):
        self._block("aws iam create-role --role-name MyRole --assume-role-policy-document file://trust.json")

    def test_delete_role(self):
        self._block("aws iam delete-role --role-name MyRole")

    def test_attach_role_policy(self):
        self._block("aws iam attach-role-policy --role-name MyRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess")

    def test_put_role_policy(self):
        self._block("aws iam put-role-policy --role-name MyRole --policy-name MyPolicy --policy-document file://policy.json")

    def test_create_user(self):
        self._block("aws iam create-user --user-name alice")

    def test_create_access_key(self):
        self._block("aws iam create-access-key --user-name alice")

    # --- Lambda mutations ---
    def test_create_function(self):
        self._block("aws lambda create-function --function-name my-fn --runtime python3.11 --role arn:... --handler index.handler --zip-file fileb://fn.zip")

    def test_delete_function(self):
        self._block("aws lambda delete-function --function-name my-fn")

    def test_update_function_code(self):
        self._block("aws lambda update-function-code --function-name my-fn --zip-file fileb://fn.zip")

    def test_invoke_function(self):
        self._block("aws lambda invoke --function-name my-fn /tmp/output.json")

    # --- RDS mutations ---
    def test_create_db_instance(self):
        self._block("aws rds create-db-instance --db-instance-identifier mydb --db-instance-class db.t3.micro --engine mysql --master-username admin --master-user-password secret")

    def test_delete_db_instance(self):
        self._block("aws rds delete-db-instance --db-instance-identifier mydb --skip-final-snapshot")

    def test_modify_db_instance(self):
        self._block("aws rds modify-db-instance --db-instance-identifier mydb --db-instance-class db.t3.small")

    # --- CloudFormation mutations ---
    def test_create_stack(self):
        self._block("aws cloudformation create-stack --stack-name MyStack --template-body file://template.yaml")

    def test_delete_stack(self):
        self._block("aws cloudformation delete-stack --stack-name MyStack")

    def test_update_stack(self):
        self._block("aws cloudformation update-stack --stack-name MyStack --template-body file://template.yaml")

    def test_deploy(self):
        self._block("aws cloudformation deploy --template-file template.yaml --stack-name MyStack")

    # --- DynamoDB mutations ---
    def test_dynamodb_put_item(self):
        self._block("aws dynamodb put-item --table-name MyTable --item file://item.json")

    def test_dynamodb_delete_item(self):
        self._block("aws dynamodb delete-item --table-name MyTable --key file://key.json")

    def test_dynamodb_update_item(self):
        self._block("aws dynamodb update-item --table-name MyTable --key file://key.json --update-expression 'SET #n = :v'")

    def test_dynamodb_create_table(self):
        self._block("aws dynamodb create-table --table-name NewTable --attribute-definitions AttributeName=id,AttributeType=S --key-schema AttributeName=id,KeyType=HASH --billing-mode PAY_PER_REQUEST")

    # --- Compound commands — blocked if ANY part is a write ---
    def test_compound_read_then_write(self):
        self._block("aws ec2 describe-instances && aws ec2 terminate-instances --instance-ids i-abc")

    def test_compound_write_then_read(self):
        self._block("aws ec2 run-instances --image-id ami-12345 --instance-type t3.micro && aws ec2 describe-instances")

    def test_pipe_write_through_jq(self):
        # The first command is a write — piping to jq doesn't make it safe.
        self._block("aws s3api put-object --bucket b --key k --body f | jq .")

    # --- command substitution of a write ---
    def test_command_substitution_write(self):
        self._block("ID=$(aws ec2 run-instances --image-id ami-12345 --instance-type t3.micro --query 'Instances[0].InstanceId' --output text)")


class TestS3CpDownloadDetection(unittest.TestCase):
    """Focused tests for the s3 cp direction logic."""

    def test_s3_to_local(self):
        self.assertTrue(is_s3_cp_download("aws s3 cp s3://bucket/key.txt /tmp/key.txt"))

    def test_local_to_s3(self):
        self.assertFalse(is_s3_cp_download("aws s3 cp /tmp/key.txt s3://bucket/key.txt"))

    def test_s3_to_s3(self):
        self.assertFalse(is_s3_cp_download("aws s3 cp s3://src/key s3://dst/key"))

    def test_s3_to_local_with_flags(self):
        self.assertTrue(is_s3_cp_download("aws s3 cp --sse AES256 s3://bucket/file.txt ./file.txt"))


class TestInvocationParsing(unittest.TestCase):
    """Unit tests for is_invocation_allowed."""

    def _allowed(self, cmd: str) -> None:
        ok, reason = is_invocation_allowed(cmd)
        self.assertTrue(ok, f"Expected ALLOW: {cmd!r}  reason={reason!r}")

    def _blocked(self, cmd: str) -> None:
        ok, reason = is_invocation_allowed(cmd)
        self.assertFalse(ok, f"Expected BLOCK: {cmd!r}")

    def test_check_dns_availability(self):
        self._allowed("aws route53domains check-domain-availability --domain-name example.com")

    def test_search_resources(self):
        self._allowed("aws resourcegroupstaggingapi get-resources")

    def test_lookup_events(self):
        self._allowed("aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances")

    def test_filter_log_events(self):
        self._allowed("aws logs filter-log-events --log-group-name /aws/lambda/my-function")

    def test_no_subcommand(self):
        self._blocked("aws ec2")

    def test_unparseable(self):
        # Unclosed quote — tokenisation fails.
        ok, _ = is_invocation_allowed("aws ec2 describe-instances --filters 'Name=state")
        # May or may not be allowed depending on shlex behaviour; ensure no crash.
        self.assertIsInstance(ok, bool)


class TestHeredocFalsePositivePrevention(unittest.TestCase):
    """
    Commands that write heredoc content containing 'aws' to a file or pipe —
    the aws text is not being executed, so these must be ALLOWED.
    """

    def _allow(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertTrue(
            allowed,
            f"Expected ALLOW (aws only in heredoc body) but got BLOCK for: {cmd!r}  blocked_inv={blocked!r}",
        )

    def test_cat_heredoc_to_file(self):
        self._allow(
            "cat > /tmp/deploy.sh <<EOF\naws ec2 run-instances --image-id ami-12345\nEOF"
        )

    def test_tee_heredoc_with_aws(self):
        self._allow(
            "tee /tmp/script.sh <<'SCRIPT'\naws s3 rm s3://bucket/file.txt\nSCRIPT"
        )

    def test_echo_heredoc_to_file(self):
        self._allow(
            "cat <<EOF > /tmp/Makefile\ndeploy:\n\taws cloudformation deploy ...\nEOF"
        )

    def test_heredoc_with_read_only_aws_in_body(self):
        # Heredoc written to file — even a read-only aws command in the body
        # should be allowed (it's not being executed here).
        self._allow(
            "cat > README.txt <<END\nRun: aws ec2 describe-instances\nEND"
        )


class TestHeredocShellExecution(unittest.TestCase):
    """
    Commands that pass a heredoc body to a shell interpreter for execution —
    any write aws invocation inside the body must be BLOCKED.
    """

    def _allow(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertTrue(allowed, f"Expected ALLOW but got BLOCK for: {cmd!r}")

    def _block(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertFalse(allowed, f"Expected BLOCK but got ALLOW for: {cmd!r}")

    # --- write operations inside shell heredoc → must be blocked ---
    def test_bash_heredoc_run_instances(self):
        self._block(
            "bash <<EOF\naws ec2 run-instances --image-id ami-12345 --instance-type t3.micro\nEOF"
        )

    def test_sh_heredoc_s3_rm(self):
        self._block("sh <<'EOF'\naws s3 rm s3://my-bucket/file.txt\nEOF")

    def test_bash_heredoc_create_stack(self):
        self._block(
            "bash <<SCRIPT\naws cloudformation create-stack --stack-name test --template-body file://t.yaml\nSCRIPT"
        )

    def test_bash_heredoc_delete_function(self):
        self._block("bash <<EOF\naws lambda delete-function --function-name my-fn\nEOF")

    # --- read-only aws commands inside shell heredoc → must be allowed ---
    def test_bash_heredoc_describe_instances(self):
        self._allow(
            "bash <<EOF\naws ec2 describe-instances --filters Name=instance-state-name,Values=running\nEOF"
        )

    def test_sh_heredoc_list_buckets(self):
        self._allow("sh <<EOF\naws s3api list-buckets\nEOF")


class TestBashCInlineExecution(unittest.TestCase):
    """
    Commands using bash -c / sh -c with an inline aws invocation.
    Write operations must be BLOCKED; read-only must be ALLOWED.
    """

    def _allow(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertTrue(allowed, f"Expected ALLOW but got BLOCK for: {cmd!r}")

    def _block(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertFalse(allowed, f"Expected BLOCK but got ALLOW for: {cmd!r}")

    # --- write operations → must be blocked ---
    def test_bash_c_run_instances(self):
        self._block("bash -c 'aws ec2 run-instances --image-id ami-12345 --instance-type t3.micro'")

    def test_sh_c_s3_rm(self):
        self._block("sh -c 'aws s3 rm s3://my-bucket/important.txt'")

    def test_bash_c_double_quoted_write(self):
        self._block('bash -c "aws lambda delete-function --function-name my-fn"')

    def test_bash_flags_before_c(self):
        self._block("bash -x -e -c 'aws ec2 terminate-instances --instance-ids i-abc'")

    def test_sh_c_iam_create_user(self):
        self._block("sh -c 'aws iam create-user --user-name alice'")

    # --- read-only operations → must be allowed ---
    def test_bash_c_describe(self):
        self._allow("bash -c 'aws ec2 describe-instances'")

    def test_sh_c_list_buckets(self):
        self._allow("sh -c 'aws s3api list-buckets'")

    def test_bash_c_sts(self):
        self._allow("bash -c 'aws sts get-caller-identity'")


class TestPipedToAws(unittest.TestCase):
    """
    Explicit tests for commands where aws is the *receiver* of a pipe.
    These are already covered implicitly but deserve their own class.
    """

    def _allow(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertTrue(allowed, f"Expected ALLOW but got BLOCK for: {cmd!r}")

    def _block(self, cmd: str) -> None:
        allowed, blocked = evaluate_command(cmd)
        self.assertFalse(allowed, f"Expected BLOCK but got ALLOW for: {cmd!r}")

    def test_cat_pipe_to_s3api_put_blocked(self):
        self._block(
            "cat data.json | aws s3api put-object --bucket my-bucket --key data.json --body -"
        )

    def test_echo_pipe_to_sqs_send_blocked(self):
        self._block(
            'echo \'{"message":"hello"}\' | aws sqs send-message --queue-url https://sqs.amazonaws.com/123/Q --message-body -'
        )

    def test_cat_pipe_to_describe_allowed(self):
        # Piping to a read-only aws command is fine.
        self._allow("cat ids.txt | aws ec2 describe-instances")

    def test_heredoc_pipe_to_s3api_put_blocked(self):
        self._block(
            "cat <<EOF | aws s3api put-object --bucket b --key k --body -\n{}\nEOF"
        )

    def test_heredoc_pipe_to_get_allowed(self):
        self._allow("cat <<EOF | aws ec2 describe-instances\ni-abc\nEOF")

    def test_aws_pipe_to_jq_read_allowed(self):
        # aws on LEFT side of pipe doing a read — allowed.
        self._allow("aws ec2 describe-instances | jq '.Reservations[]'")

    def test_aws_write_pipe_to_jq_blocked(self):
        # aws on LEFT side of pipe doing a WRITE — still blocked.
        self._block("aws ec2 run-instances --image-id ami-12345 --instance-type t3.micro | jq .")


if __name__ == "__main__":
    unittest.main(verbosity=2)
