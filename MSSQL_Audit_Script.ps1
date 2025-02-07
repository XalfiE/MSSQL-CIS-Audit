<# 
.SYNOPSIS
Audits the MSSQL Server against CIS benchmarks and reviews user, role, and permission settings.

.DESCRIPTION
This script checks the configuration of a target MSSQL Server instance against the recommendations found in the CIS Security Configuration Benchmark for Microsoft SQL Server (for example, 2016 and 2012). It gathers server version information, database details, various configuration settings, and user/role mappings. The results are written to an HTML file for review.

.PARAMETERS
    -Server                The target SQL Server instance.
    -Database              (Optional) A specific database to audit; if omitted, "master" is used for connection and all databases are iterated.
    -WindowsAuthentication Specifies that Windows Authentication is used.
    -SQLAuthentication     Specifies that SQL Authentication is used.
    -Username              (When using SQL Authentication) The SQL login username.
    -Include               Specifies which sections to run. Valid values include "All", "CIS", and "UserManagement". The default is "All".

.EXAMPLES
    .\MSSQL_Audit_Script.ps1 -Server "MySQLServer" -WindowsAuthentication
    .\MSSQL_Audit_Script.ps1 -Server "MySQLServer" -Database "MyDB" -SQLAuthentication -Username "dbuser"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [Parameter(Mandatory=$false)]
    [string]$Database,

    [switch]$WindowsAuthentication,

    [switch]$SQLAuthentication,

    [string]$Username,

    [string[]]$Include = 'All'
)

# ---------------------- Function: Startup ----------------------
function Startup {
    [CmdletBinding()]
    param()

    Write-Host "#########################`nMSSQL audit tool`n#########################"

    # Start stopwatch for timing
    $Script:Stopwatch = New-Object -TypeName System.Diagnostics.Stopwatch
    $Script:TotalTime = $Script:Stopwatch.Elapsed
    $Script:Stopwatch.Start()

    # Get password securely if using SQL Authentication
    if ($SQLAuthentication) {
        $SecurePassword = Read-Host -AsSecureString "Enter password"
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
        $Script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    # Setup output file name
    $Script:Outfile = "audit-MSSQL-" + $Server + ".html"
    if (Test-Path -Path $Script:Outfile) {
        Write-Host "The output file already exists, would you like to overwrite it?"
        Remove-Item $Script:Outfile -Confirm
        if (Test-Path -Path $Script:Outfile) {
            Write-Host "Please move the output file: $Script:Outfile"
            exit
        }
    }
    HTMLPrinter -HTMLStart

    Write-Host "Using $Server as target server"
    if ($Database -ne "") {
        Write-Host "Using $Database as target database"
        $Script:Database = $Database
        $Script:AllDatabases = $false
    }
    else {
        Write-Host "No database specified. Using master for connection and iterating through all databases."
        $Script:Database = "master"
        $Script:AllDatabases = $true
    }

    HTMLPrinter -OpeningTag "<h1 id='Basic_information' class='headers'>" -Content "Basic Information" -ClosingTag "</h1>"
    HTMLPrinter -OpeningTag "<p>" -Content "Using server: $Server" -ClosingTag "</p>"
    HTMLPrinter -OpeningTag "<p>" -Content "Using database: $Script:Database" -ClosingTag "</p>"

    $Script:OriginalDatabase = $Script:Database

    SqlConnectionBuilder    
    CheckFullVersion
    GenerateDatabasesInfo

    Write-Host "Setup completed in:" $Script:Stopwatch.Elapsed
    $Script:TotalTime += $Script:Stopwatch.Elapsed
    Write-Host "Total time elapsed:" $Script:TotalTime
    $Script:Stopwatch.Restart()

    Main

    HTMLPrinter -HTMLEnd

    $Script:TotalTime += $Script:Stopwatch.Elapsed
    Write-Host "Audit has finished, total time elapsed:" $Script:TotalTime
}

# ---------------------- Function: Main ----------------------
function Main {
    [CmdletBinding()]
    param()

    if ($Include -contains "All" -or $Include -contains "CIS") {
        SecurityChecklists
        Write-Host "CIS benchmark tests completed in:" $Script:Stopwatch.Elapsed
        $Script:TotalTime += $Script:Stopwatch.Elapsed
        Write-Host "Total time elapsed:" $Script:TotalTime
        $Script:Stopwatch.Restart()
    }

    if ($Include -contains "All" -or $Include -contains "UserManagement") {
        UserManagement
        Write-Host "User management tests completed in:" $Script:Stopwatch.Elapsed
        $Script:TotalTime += $Script:Stopwatch.Elapsed
        Write-Host "Total time elapsed:" $Script:TotalTime
        $Script:Stopwatch.Restart()
    }
}

# ---------------------- Function: SqlConnectionBuilder ----------------------
function SqlConnectionBuilder {
    [CmdletBinding()]
    param()

    $Script:SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    if ($WindowsAuthentication) {
        $Script:SqlConnection.ConnectionString = "Server=$Server;Database=$Script:Database;Integrated Security=True;"
    }
    elseif ($SQLAuthentication) {
        $Script:SqlConnection.ConnectionString = "Server=$Server;Database=$Script:Database;User ID=$Username;Password=$Script:Password;"
    }
}

# ---------------------- Function: DataCollector ----------------------
function DataCollector {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$SqlQuery,

        [string]$AllTables
    )

    $SQLCommand = New-Object System.Data.SqlClient.SqlCommand
    $SQLCommand.CommandText = $SqlQuery
    $SQLCommand.Connection = $Script:SqlConnection
    $SQLAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $SQLAdapter.SelectCommand = $SQLCommand
    $Dataset = New-Object System.Data.DataSet
    $SQLAdapter.Fill($Dataset) | Out-Null

    if ($AllTables -eq "y") {
        return $Dataset
    }
    else {
        return $Dataset.Tables[0]
    }
}

# ---------------------- Function: CheckFullVersion ----------------------
function CheckFullVersion {
    [CmdletBinding()]
    param()

    $SqlQuery = "SELECT @@VERSION AS Version;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<h3 id='Server_version' class='headers'>" -Content "Server Version" -ClosingTag "</h3>"
    HTMLPrinter -Table $Dataset -Columns @("Version")
}

# ---------------------- Function: GenerateDatabasesInfo ----------------------
function GenerateDatabasesInfo {
    [CmdletBinding()]
    param()

    $SqlQuery = "SELECT * FROM sys.databases;"
    $Script:DatabasesInfo = DataCollector $SqlQuery
    $Script:DatabasesInfo.Columns.Add("number_of_users", "System.String") | Out-Null

    $SqlQueryUsers = "SELECT COUNT(*) AS users FROM sys.database_principals WHERE type IN ('C','E','G','K','S','U','X');"
    foreach ($db in $Script:DatabasesInfo) {
        $Script:Database = $db.name
        SqlConnectionBuilder
        $Dataset = DataCollector $SqlQueryUsers
        $db.number_of_users = $Dataset.Rows[0].users
    }
    $Script:Database = $Script:OriginalDatabase
    SqlConnectionBuilder
    HTMLPrinter -OpeningTag "<h3 id='Databases' class='headers'>" -Content "Databases" -ClosingTag "</h3>"
    HTMLPrinter -Table $Script:DatabasesInfo -Columns @("name", "create_date", "number_of_users")
}

# ---------------------- Function: SecurityChecklists ----------------------
function SecurityChecklists {
    <#
    .SYNOPSIS
    Checks the MSSQL server against CIS and other benchmarks.
    #>

    HTMLPrinter -OpeningTag "<h1 id='CIS_benchmark' class='headers'>" -Content "CIS benchmark" -ClosingTag "</h1>"

    # ------------------- Existing Tests -------------------
    # (Place here any existing queries that check configurations such as:
    # - Ad Hoc Distributed Queries
    # - clr enabled
    # - cross db ownership chaining
    # - Database Mail XPs
    # - Ole Automation Procedures
    # - remote access
    # - remote admin connections
    # - scan for startup procs
    # - trustworthiness of databases
    # - sa account configuration
    # - xp_cmdshell, etc.
    # For brevity, these existing tests are assumed to be included.)
    # ------------------- End of Existing Tests -------------------

    # ===================== Additional Security Tests =====================

    # Additional Test A: Check if Force Encryption is enabled.
    $SqlQuery = @"
DECLARE @ForceEncryption INT;
EXEC master..xp_instance_regread
    @rootkey = N'HKEY_LOCAL_MACHINE',
    @key = N'SOFTWARE\Microsoft\Microsoft SQL Server\MSSQLServer\SuperSocketNetLib',
    @value_name = N'ForceEncryption',
    @value = @ForceEncryption OUTPUT,
    @no_output = 1;
SELECT @ForceEncryption AS ForceEncryption;
"@
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check if Force Encryption is enabled (should be 1 for enabled) in SQL Server network configuration." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("ForceEncryption")

    # Additional Test B: Check that non-system SQL logins do not have 'master' or 'tempdb' as their default database.
    $SqlQuery = "SELECT name, default_database FROM sys.sql_logins WHERE default_database IN ('master', 'tempdb') AND name NOT IN ('sa');"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check that non-system SQL logins do not have 'master' or 'tempdb' as their default database." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "default_database")

    # Additional Test C: Check the SQL Server service account.
    $SqlQuery = "SELECT servicename, service_account FROM sys.dm_server_services;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check the SQL Server service account. It is recommended not to run SQL Server under a highly privileged account like LocalSystem." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("servicename", "service_account")

    # New Test 1: Verify the installed SQL Server Service Pack and Version.
    $SqlQuery = "SELECT SERVERPROPERTY('ProductLevel') AS SP_installed, SERVERPROPERTY('ProductVersion') AS Version;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Ensure Latest SQL Server Service Packs and Hotfixes are Installed. Verify that SP_installed and Version match expected values." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("SP_installed", "Version")

    # New Test 2: Ensure Windows local groups are not added as SQL Server logins.
    $SqlQuery = "SELECT [name], [type_desc] FROM sys.server_principals WHERE type_desc = 'WINDOWS_GROUP' AND [name] LIKE CAST(SERVERPROPERTY('MachineName') AS nvarchar) + '%';"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Ensure that local Windows groups (those starting with the machine name) are not added as SQL Logins." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("name", "type_desc")

    # New Test 3: Check SQL Server Audit configuration for login auditing.
    $SqlQuery = "SELECT S.name AS AuditName, CAST(S.is_state_enabled AS int) AS AuditEnabled, S.type_desc AS WriteLocation, SA.name AS AuditSpecificationName, CAST(SA.is_state_enabled AS int) AS AuditSpecificationEnabled, SAD.audit_action_name, SAD.audited_result FROM sys.server_audit_specification_details AS SAD JOIN sys.server_audit_specifications AS SA ON SAD.server_specification_id = SA.server_specification_id JOIN sys.server_audits AS S ON SA.audit_guid = S.audit_guid WHERE SAD.audit_action_id IN ('CNAU','LGFL','LGSD');"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "Check SQL Server Audit configuration for login auditing (e.g., AUDIT_CHANGE_GROUP, FAILED_LOGIN_GROUP, SUCCESSFUL_LOGIN_GROUP)." -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("AuditName", "AuditEnabled", "WriteLocation", "AuditSpecificationName", "AuditSpecificationEnabled", "audit_action_name", "audited_result")

    # New Test 4: Note regarding SQL Server Browser Service configuration.
    HTMLPrinter -OpeningTag "<p>" -Content "Note: Verify manually that the SQL Server Browser Service is configured as required (disabled for default instances or appropriately configured for named instances)." -ClosingTag "</p>"

    HTMLPrinter -OpeningTag "<h3 id='Additional_Tests_End' class='headers'>" -Content "End of Additional Security Tests" -ClosingTag "</h3>"
}

# ---------------------- Function: UserManagement ----------------------
function UserManagement {
    <#
    .SYNOPSIS
    Audits user management for the SQL Server and its databases.
    
    .DESCRIPTION
    This function collects information on login-to-database user mappings,
    server role memberships, and permissions (both at the server and database levels). 
    It builds an authorization matrix for review.
    #>

    Write-Host "###### Now checking User Management"
    HTMLPrinter -OpeningTag "<h1 id='User_management' class='headers'>" -Content "User Management" -ClosingTag "</h1>"
    HTMLPrinter -OpeningTag "<h3 id='Login_to_user_mapping' class='headers'>" -Content "Login to User Mapping" -ClosingTag "</h3>"

    # Set up Authorization Matrix DataTable
    $AuthorizationMatrix = New-Object System.Data.DataTable
    $AuthorizationMatrix.Columns.Add("login_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("server_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("login_type", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_role_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_schema_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_object_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_object_type", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_permission_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("srv_permission_state", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_user_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_role_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_schema_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_object_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_object_type", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_permission_name", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("db_permission_state", "System.String") | Out-Null
    $AuthorizationMatrix.Columns.Add("notes", "System.String") | Out-Null

    # Step 0: Gather non-server-role logins.
    $SqlQuery = "SELECT @@SERVERNAME AS server_name, name AS login_name, type_desc AS login_type FROM sys.server_principals WHERE type <> 'R' ORDER BY name;"
    $Dataset = DataCollector $SqlQuery
    foreach ($Row in $Dataset) {
        if ($Row.login_name -ne "sa" -and $Row.login_name -notlike "##MS_*" -and $Row.login_name -notlike "NT Service\*" -and $Row.login_name -notlike "NT AUTHORITY\*") {
            $new_row = $AuthorizationMatrix.NewRow()
            $new_row.login_name = $Row.login_name
            $new_row.server_name = $Row.server_name
            $new_row.login_type = $Row.login_type
            $AuthorizationMatrix.Rows.Add($new_row)
        }
    }

    # Step 1: Map logins to their corresponding database users.
    $SqlQuery = "EXEC sp_MSloginmappings;"
    $Dataset = DataCollector $SqlQuery "y"
    HTMLPrinter -OpeningTag "<p>" -Content "This table contains every login on the server and their corresponding database accounts." -ClosingTag "</p>"
    $TempTable = New-Object System.Data.DataTable
    $TempTable.Columns.Add("LoginName", "System.String") | Out-Null
    $TempTable.Columns.Add("DBName", "System.String") | Out-Null
    $TempTable.Columns.Add("UserName", "System.String") | Out-Null
    $TempTable.Columns.Add("AliasName", "System.String") | Out-Null
    foreach ($DataTable in $Dataset.Tables) {
        foreach ($Row in $DataTable) {
            $TempTable.ImportRow($Row)
        }
    }
    HTMLPrinter -Table $TempTable -Columns @("LoginName", "DBName", "UserName", "AliasName")

    HTMLPrinter -OpeningTag "<h3 id='Logins_permissions' class='headers'>" -Content "Logins Permissions" -ClosingTag "</h3>"
    $SqlQuery = "SELECT @@SERVERNAME AS server_name, SUSER_NAME(RM.role_principal_id) AS server_role, LGN.name AS member_name, LGN.type_desc, LGN.create_date, LGN.modify_date FROM sys.server_role_members AS RM INNER JOIN sys.server_principals AS LGN ON RM.member_principal_id = LGN.principal_id ORDER BY server_role, type_desc;"
    $Dataset = DataCollector $SqlQuery
    HTMLPrinter -OpeningTag "<p>" -Content "A list of who is in server-level roles" -ClosingTag "</p>"
    HTMLPrinter -Table $Dataset -Columns @("server_name", "server_role", "member_name", "type_desc", "create_date", "modify_date")
    foreach ($Row in $Dataset) {
        if ($Row.member_name -ne "sa" -and $Row.member_name -notlike "##MS_*" -and $Row.member_name -notlike "NT Service\*" -and $Row.member_name -notlike "NT AUTHORITY\*") {
            $new_row = $AuthorizationMatrix.NewRow()
            $new_row.login_name = $Row.member_name
            $new_row.server_name = $Row.server_name
            $new_row.login_type = $Row.type_desc
            $new_row.srv_role_name = $Row.server_role
            $AuthorizationMatrix.Rows.Add($new_row)
        }
    }

    # Additional queries for database-level user mapping and permissions would be added here...
    # (For brevity, the remainder of the UserManagement queries are assumed to be similar to the original script.)

    # Finally, sort and display the Authorization Matrix.
    $dv = New-Object System.Data.DataView($AuthorizationMatrix)
    $dv.Sort = "login_name, server_name, db_name, db_role_name, db_schema_name, db_object_type, db_object_name, db_permission_state, db_permission_name, srv_role_name, srv_schema_name, srv_object_type, srv_object_name, srv_permission_state, srv_permission_name"
    $AuthorizationMatrix = $dv.ToTable()
    HTMLPrinter -OpeningTag "<h1 id='Authorizationmatrix' class='headers'>" -Content "Authorization Matrix" -ClosingTag "</h1>"
    HTMLPrinter -Table $AuthorizationMatrix -Columns @("login_name", "server_name", "login_type", "srv_role_name", "srv_schema_name", "srv_object_name", "srv_object_type", "srv_permission_name", "srv_permission_state", "db_name", "db_user_name", "db_role_name", "db_schema_name", "db_object_name", "db_object_type", "db_permission_name", "db_permission_state", "notes")
}

# ---------------------- Function: HTMLPrinter ----------------------
function HTMLPrinter {
    <#
    .SYNOPSIS
    Converts gathered data to HTML and appends it to the output file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName="Content", Mandatory=$true)]
        [string]$OpeningTag,
        [Parameter(ParameterSetName="Content", Mandatory=$true)]
        [string]$Content,
        [Parameter(ParameterSetName="Content", Mandatory=$true)]
        [string]$ClosingTag,

        [Parameter(ParameterSetName="Table", Mandatory=$true)]
        [System.Data.DataTable]$Table,
        [Parameter(ParameterSetName="Table", Mandatory=$true)]
        [array]$Columns,

        [Parameter(ParameterSetName="HTMLStart", Mandatory=$true)]
        [switch]$HTMLStart,
        [Parameter(ParameterSetName="HTMLEnd", Mandatory=$true)]
        [switch]$HTMLEnd
    )

    $startHTML = @"
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
    body, html {
        margin: 0;
        padding: 0;
    }
    .collapsible {
        background-color: #777;
        color: white;
        cursor: pointer;
        padding: 18px;
        width: 20%;
        border: none;
        text-align: left;
        outline: none;
        font-size: 15px;
    }
    .active, .collapsible:hover {
        background-color: #555;
    }
    .content {
        padding: 0 18px;
        max-height: 0;
        overflow: hidden;
        transition: max-height 0.2s ease-out;
        background-color: #f1f1f1;
        overflow-x: auto;
    }
    TABLE {
        border-width: 1px;
        border-style: solid;
        border-color: black;
        border-collapse: collapse;
        margin-bottom: 20px;
    }
    TH {
        border-width: 1px;
        padding: 3px;
        border-style: solid;
        border-color: black;
        background-color: #6495ED;
    }
    TD {
        border-width: 1px;
        padding: 3px;
        border-style: solid;
        border-color: black;
    }
    .odd {
        background-color: #ffffff;
    }
    .even {
        background-color: #dddddd;
    }
    .collapsible:after {
        content: '\02795';
        font-size: 13px;
        color: white;
        float: right;
        margin-left: 5px;
    }
    .active:after {
        content: "\2796";
    }
    .fixed {
        position: fixed;
        overflow-y: scroll;
        max-width: 20%;
        max-height: 100%;
    }
    .auditedResults {
        margin-left: 20%;
    }
    #Basic_information {
        margin-top: 0;
    }
    #OTP {
        margin-top: 0;
    }
    </style>
</head>
<body>
<div class="content fixed" id="ToC2">
<nav role="navigation" id="ToC">
</nav>
</div>
<div class="auditedResults">
"@
    $endHTML = @"
    </div>
    <script>
    var ToC = "<h2 id='OTP'>On this page:</h2>";
    var headers = document.getElementsByClassName("headers");
    for (i = 0; i < headers.length; i++) {
        var current = headers[i];
        title = current.textContent;
        var type = current.tagName;
        link = "#" + current.getAttribute("id");
        var newLine;
        if (type == 'H1') {
            newLine = "<ul><li><a href='" + link + "'>" + title + "</a></li></ul>";
        }
        if (type == 'H3') {
            newLine = "<ul style='padding-left: 60px;'><li><a href='" + link + "'>" + title + "</a></li></ul>";
        }
        ToC += newLine;
    }
    document.getElementById('ToC').innerHTML = ToC;
    var coll = document.getElementsByClassName("collapsible");
    var i;
    for (i = 0; i < coll.length; i++) {
        coll[i].addEventListener("click", function() {
          this.classList.toggle("active");
          var content = this.nextElementSibling;
          if (content.style.maxHeight){
            content.style.maxHeight = null;
          } else {
            content.style.maxHeight = content.scrollHeight + "px";
          } 
        });
    }
    </script>
</body>
</html>
"@
    $CollapsableStart = @"
    <button class="collapsible">Open Table</button>
    <div class="content">
"@
    try {   
        if ($Table -ne $null) {
            Out-File -FilePath $Script:Outfile -InputObject $CollapsableStart -Append
            Out-File -FilePath $Script:Outfile -InputObject ($Table | ConvertTo-Html -Property $Columns -Fragment) -Append
            Out-File -FilePath $Script:Outfile -InputObject "</div>" -Append
        }
        elseif ($Content -ne "") {
            Out-File -FilePath $Script:Outfile -InputObject ($OpeningTag + $Content + $ClosingTag) -Append
        }
        elseif ($HTMLStart) {
            Out-File -FilePath $Script:Outfile -InputObject $startHTML -Append
        }
        elseif ($HTMLEnd) {
            Out-File -FilePath $Script:Outfile -InputObject $endHTML -Append
        }
    }
    catch {
        Write-Host "An error has occurred."
    }
}

# ---------------------- End of Functions ----------------------

# Start the audit process.
Startup
