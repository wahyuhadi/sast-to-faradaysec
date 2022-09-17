# SAST to faradaysec

- example 
```
    $semgrep --config=auto --json >> semgrep.json
    $sast-to-faradaysec -i semgrep.json -r project_name
```