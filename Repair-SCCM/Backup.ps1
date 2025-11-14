    Write-LogMessage -Level Info -Message "--- Step 3: Download SCCM Installation Files ---"
    Write-LogMessage -Level Default -Message "Preparing SCCM installation files for $t"
    try {
        # Determine source path based on SCCM site code
        # Each site has its own distribution point with site-specific client files
        if ( $siteCode -eq "DDS" ) {
            $cpSource = "\\scanz223\SMS_DDS\Client"     # DDS site distribution point
        }
        elseif ( $siteCode -eq "PCI" ) {
            $cpSource = "\\slrcp223\SMS_PCI\Client"     # PCI site distribution point
        }
        
        # Set standardized destination path on target computer
        # This location will be used by the reinstall script
        $cpDestination = "\\$t\c$\drivers\ccm\ccmsetup"
        $localDestPath = "C:\Drivers\ccm\ccmsetup"

        if (Test-Path $cpSource) {
            Write-LogMessage -Level Success -Message "SCCM distribution point source found: $cpSource"
        }
        else {
            throw "SCCM distribution point source not reachable: $cpSource"
        }
    
        Write-LogMessage -Level Info -Message "Destination: $localDestPath on $t"
        
        # Remove destination directory if it exists to delete any old install files
        # Use Invoke-Command to perform operations locally on target machine to avoid UNC permission issues
        Write-LogMessage -Level Default -Message "Preparing destination directory on $t"
        try {
            Invoke-Command -ComputerName $t -ScriptBlock {
                param($destPath)
                if (Test-Path $destPath) {
                    # Clear attributes and force remove any existing files
                    Get-ChildItem $destPath -Recurse -Force | ForEach-Object {
                        $_.Attributes = 'Normal'
                    }
                    Remove-Item $destPath -Force -Recurse -ErrorAction SilentlyContinue
                }
                # Create fresh destination directory
                New-Item $destPath -Force -ItemType Directory | Out-Null
            } -ArgumentList $localDestPath -ErrorAction Stop
            
            Write-LogMessage -Level Success -Message "Prepared destination directory on $t"
        }
        catch {
            Write-LogMessage -Level Error -Message "Failed to prepare destination directory on $t. Error: $_"
            throw $_
        }

        # Copy SCCM installation files using Robocopy for better reliability with network paths and file locks
        # Robocopy is more robust than Copy-Item for handling locked files and network operations
        Write-LogMessage -Level Default -Message "Starting file copy using Robocopy for improved reliability"
        try {
            # Use Robocopy with retry options and file attribute overrides
            # /E = Copy subdirectories including empty ones
            # /R:3 = Retry 3 times on failed copies  
            # /W:5 = Wait 5 seconds between retries
            # /IS = Include Same files (overwrite)
            # /IT = Include Tweaked files (different attributes)
            # /IM = Include Modified files
            # /XJ = Exclude Junction points
            # /NP = No Progress (cleaner output)
            # /NDL = No Directory List
            # /NFL = No File List (unless error)
            $robocopyArgs = @(
                "`"$cpSource`"",
                "`"$cpDestination`"",
                "/E", "/R:3", "/W:5", "/IS", "/IT", "/IM", "/XJ", "/NP", "/NDL", "/NFL"
            )
            
            $robocopyResult = & robocopy @robocopyArgs
            $robocopyExitCode = $LASTEXITCODE
            
            # Robocopy exit codes: 0=No files copied, 1=Files copied successfully, 2=Extra files/dirs found and removed
            # 4=Mismatched files/dirs found, 8=Failed to copy some files, 16=Serious error
            if ($robocopyExitCode -ge 8) {
                throw "Robocopy failed with exit code $robocopyExitCode. Output: $($robocopyResult -join "`n")"
            }
            
            Write-LogMessage -Level Success -Message "SCCM installation files copied successfully to $t using Robocopy (Exit Code: $robocopyExitCode)"
        }
        catch {
            Write-LogMessage -Level Warning -Message "Robocopy method failed: $_"
            Write-LogMessage -Level Default -Message "Attempting fallback copy method using Invoke-Command"
            
            # Fallback to remote execution method if Robocopy fails
            try {
                Invoke-Command -ComputerName $t -ScriptBlock {
                    param($source, $dest)
                    
                    # Create destination if it doesn't exist
                    if (-not (Test-Path $dest)) {
                        New-Item $dest -Force -ItemType Directory | Out-Null
                    }
                    
                    # Copy files locally on the target machine to avoid UNC issues
                    Copy-Item "$source\*" $dest -Force -Recurse -ErrorAction Stop
                    
                } -ArgumentList $cpSource, $localDestPath -ErrorAction Stop
                
                Write-LogMessage -Level Success -Message "SCCM installation files copied successfully to $t using fallback method"
            }
            catch {
                Write-LogMessage -Level Error -Message "All copy methods failed for $t. Error: $_"
                throw $_
            }
        }

        # Verify that the main installer executable exists on target computer
        # Use remote execution to avoid UNC path issues during verification
        Write-LogMessage -Level Default -Message "Verifying installation files on $t"
        try {
            $verificationResult = Invoke-Command -ComputerName $t -ScriptBlock {
                param($destPath)
                $ccmSetupPath = Join-Path $destPath "ccmsetup.exe"
                return (Test-Path $ccmSetupPath)
            } -ArgumentList $localDestPath -ErrorAction Stop
            
            if ($verificationResult) {
                Write-LogMessage -Level Success -Message "Verified ccmsetup.exe exists on $t"
            }
            else {
                throw "ccmsetup.exe not found on $t after file copy operation"
            }
        }
        catch {
            Write-LogMessage -Level Error -Message "Failed to verify installation files on $t. Error: $_"
            throw $_
        }

        Write-LogMessage -Level Success -Message "SCCM installation files prepared successfully on $t"
    } catch {
        Write-LogMessage -Level Error -Message "Failed to download SCCM installation files on $t. Error: $_"
        "$t - Failed: File download error - $_" | Out-File -Append -FilePath $remediationFail -Encoding UTF8
        exit 1
    }