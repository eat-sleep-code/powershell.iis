PowerShell script with functions to:

 Create An IIS Website
• Setup Folder
• Create Application Pool (Setting Appropriate .NET Version, Pipeline Mode, Etc.)
• Create New Website
• (Optionally) Create Virtual Directories
• Log Creation Steps
• (Optionally) Force Overwrite Of Website Content

 Remove An IIS Website
• Remove Website
• Remove An Unused Application Pool
• (Optionally) Remove The Folder, Recurses To Check For Empty Parent Folders
• Log Removal Steps

 Prepare TFS Environment
• Create A Mapping Between TFS Folder And Local Folder
• Get Latest Code From TFS Folder
• Set Appropriate Permissions For Runtime

 Bulk Actions
• Process IIS Website creations (or removals) in bulk by reading from an XML file (either local or web-hosted).
• Process TFS mapping and download in bulk by reading from an XML file (either local or web-hosted)
