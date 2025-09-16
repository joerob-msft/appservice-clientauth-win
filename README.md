# Client Certificate Demo App for Azure Web Apps

This is a simple ASP.NET Core web application designed to run on Azure Web Apps (Windows hosting) that demonstrates client certificate authentication and validation.

## Features

- **Client Certificate Detection**: Automatically detects and displays client certificates presented by the browser/client
- **Certificate Details**: Shows comprehensive certificate information including:
  - Subject and Issuer information
  - Certificate thumbprint and serial number
  - Validity dates and current status
  - Certificate version and algorithms
  - Public key information
- **Chain Validation**: Validates the entire certificate chain and reports any issues
- **Certificate Extensions**: Displays all certificate extensions and their values
- **Azure Web Apps Ready**: Pre-configured for deployment to Azure Web Apps with Windows hosting

## Local Development

1. **Prerequisites**:
   - .NET 8.0 SDK
   - A client certificate for testing (optional)

2. **Run the application**:
   ```bash
   dotnet run
   ```

3. **Test with client certificate**:
   - Install a client certificate in your browser
   - Navigate to the application URL
   - Your browser should prompt you to select a client certificate

## Azure Web Apps Deployment

### 1. Deploy the Application

You can deploy this application to Azure Web Apps using any of these methods:

- **Visual Studio**: Right-click project → Publish → Azure App Service
- **Azure CLI**:
  ```bash
  az webapp deployment source config-zip --resource-group <resource-group> --name <app-name> --src <zip-file>
  ```
- **GitHub Actions**: Use the provided workflow file

### 2. Configure Client Certificate Authentication

After deployment, enable client certificate authentication in your Azure Web App:

#### Option 1: Azure Portal
1. Go to your App Service in the Azure Portal
2. Navigate to **Configuration** → **General settings**
3. Set **Client certificate mode** to:
   - **Allow**: Client certificates are optional
   - **Require**: Client certificates are mandatory

#### Option 2: Azure CLI
```bash
# Allow client certificates (optional)
az webapp update --resource-group <resource-group> --name <app-name> --set clientCertEnabled=true

# Require client certificates (mandatory)
az webapp update --resource-group <resource-group> --name <app-name> --set clientCertEnabled=true --set clientCertMode=Required
```

#### Option 3: ARM Template
```json
{
  "type": "Microsoft.Web/sites",
  "properties": {
    "clientCertEnabled": true,
    "clientCertMode": "Optional"  // or "Required"
  }
}
```

### 3. Testing

1. **Without Client Certificate**: 
   - Navigate to your app URL
   - You should see a warning message about no client certificate detected

2. **With Client Certificate**:
   - Install a client certificate in your browser/client
   - Navigate to your app URL
   - Select the certificate when prompted
   - View detailed certificate information and validation results

## Project Structure

```
ClientCertApp/
├── Controllers/
│   └── HomeController.cs          # Main controller handling certificate display
├── Models/
│   └── CertificateInfoViewModel.cs # View model for certificate data
├── Views/
│   ├── Home/
│   │   └── Index.cshtml           # Main page displaying certificate info
│   └── Shared/
│       └── _Layout.cshtml         # Layout template
├── Program.cs                     # Application configuration and startup
├── ClientCertApp.csproj          # Project file
├── web.config                    # IIS configuration for Azure Web Apps
└── appsettings.json              # Application settings
```

## Key Configuration

The application is configured to:
- Accept all types of client certificates (`CertificateTypes.All`)
- Skip revocation checking for demo purposes (`RevocationMode.NoCheck`)
- Allow invalid certificates for testing (`ValidateValidityPeriod = false`)
- Display detailed validation information even for invalid certificates

For production use, you may want to adjust these settings to be more restrictive.

## Security Notes

- This demo application accepts any client certificate for demonstration purposes
- In production, implement proper certificate validation logic
- Consider certificate pinning or allowlisting specific CAs
- Enable proper revocation checking in production environments
- Use HTTPS-only in production (handled automatically by Azure Web Apps)

## Troubleshooting

1. **No certificate detected**:
   - Ensure `clientCertEnabled=true` in Azure Web App settings
   - Verify your browser has a client certificate installed
   - Check that the certificate is valid and trusted

2. **Chain validation failures**:
   - Common in test environments with self-signed certificates
   - Check if intermediate certificates are missing
   - Verify CA certificates are trusted

3. **Application won't start**:
   - Check the .NET version compatibility
   - Review application logs in Azure Portal → Log Stream