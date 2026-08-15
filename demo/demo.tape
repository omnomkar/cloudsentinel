Output demo/cloudsentinel.gif

Set Shell "bash"
Set FontSize 15
Set Width 1180
Set Height 640
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 12ms

Hide
Type "cd ~/projects/cloudsentinel && source venv/bin/activate && export PS1='$ ' && clear"
Enter
Sleep 3s
Show

# Scan 1: the vulnerable stack
Type "python3 main.py --cloud aws --endpoint-url http://localhost:4566 --fail-on critical --exclude-checks CLOUDTRAIL_NO_TRAIL,IAM_ROOT_NO_MFA --output-dir reports/vulnerable"
Enter
Sleep 6s

Type "echo $?"
Enter
Sleep 3s

# Swap to the remediated stack (hidden - terraform is too slow to film)
Hide
Type "clear && cd infra/vulnerable && terraform destroy -auto-approve -input=false -var='enable_cloudtrail_resource=false' > /dev/null 2>&1 && cd ../remediated && terraform apply -auto-approve -input=false -var='enable_cloudtrail_resource=false' > /dev/null 2>&1 && cd ../.. && clear"
Enter
Sleep 90s
Show

# Scan 2: the remediated stack
Type "python3 main.py --cloud aws --endpoint-url http://localhost:4566 --fail-on critical --exclude-checks CLOUDTRAIL_NO_TRAIL,IAM_ROOT_NO_MFA --output-dir reports/remediated"
Enter
Sleep 6s

Type "echo $?"
Enter
Sleep 4s