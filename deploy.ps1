# Azure Web App Deployment Script
# This script helps deploy the Client Certificate Demo App to Azure Web Apps

param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$AppName,
    
    [Parameter(Mandatory=$false)]
    [string]$Location = "East US"
)

Write-Host "Deploying Client Certificate Demo App to Azure Web Apps..." -ForegroundColor Green

# Build the application
Write-Host "Building the application..." -ForegroundColor Yellow
dotnet build --configuration Release

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed!"
    exit 1
}

# Publish the application
Write-Host "Publishing the application..." -ForegroundColor Yellow
dotnet publish --configuration Release --output ./publish

if ($LASTEXITCODE -ne 0) {
    Write-Error "Publish failed!"
    exit 1
}

# Create deployment package
Write-Host "Creating deployment package..." -ForegroundColor Yellow
Compress-Archive -Path ./publish/* -DestinationPath ./deployment.zip -Force

# Deploy to Azure (requires Azure CLI)
Write-Host "Deploying to Azure Web App: $AppName" -ForegroundColor Yellow

# Enable client certificates
Write-Host "Enabling client certificate authentication..." -ForegroundColor Yellow
az webapp update --resource-group $ResourceGroupName --name $AppName --set clientCertEnabled=true

# Deploy the package
az webapp deployment source config-zip --resource-group $ResourceGroupName --name $AppName --src ./deployment.zip

if ($LASTEXITCODE -eq 0) {
    Write-Host "Deployment completed successfully!" -ForegroundColor Green
    Write-Host "Your app is available at: https://$AppName.azurewebsites.net" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "To configure client certificate mode:" -ForegroundColor Yellow
    Write-Host "  Allow (optional): az webapp update --resource-group $ResourceGroupName --name $AppName --set clientCertMode=Optional" -ForegroundColor Gray
    Write-Host "  Require (mandatory): az webapp update --resource-group $ResourceGroupName --name $AppName --set clientCertMode=Required" -ForegroundColor Gray
} else {
    Write-Error "Deployment failed!"
    exit 1
}

# Cleanup
Remove-Item ./deployment.zip -Force
Remove-Item ./publish -Recurse -Force