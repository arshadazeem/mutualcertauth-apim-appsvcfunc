# mutualcertauth-apim-appsvcfunc
This application validates incoming client certificates in Azure Functions or App Services using Java.

This can be easily integrated with any client of an Azure function/AppService. E.g. If APIM is infront of the Function/AppService, we can enable client cert authentication on APIM (as documented at https://docs.microsoft.com/en-us/azure/api-management/api-management-howto-mutual-certificates), and pass APIMs client certs to the backend Functon/AppService)

<b>1. Steps to Build: </b>

``mvn clean package``

<b>2. Deploy to Azure:</b>


``mvn azure-functions:deploy``

<b>To run locally:</b>
``mvn azure-functions:run``
