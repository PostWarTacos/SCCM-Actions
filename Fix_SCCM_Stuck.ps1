$c=(gwmi -Namespace root\ccm\SoftMgmtAgent -Class CCM_TSExecutionRequest -Filter "State = 'Completed' And CompletionState = 'Failure'"); if ($c) {$c.Delete();} 
Start-Sleep -Seconds 10
Restart-Service ccmexec -force
Return "Process Completed"