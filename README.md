# mutualcertauth-apim-appsvcfunc
This application validates incoming client certificates in Azure Functions or App Services using Java.

This can be easily integrted with any client of an Azure function (e.g. By enabling mutual client cert authentication on APIM, and passing APIMs client certs to the backend Functon/AppService)

<b>1. Steps to Build: </b>

``mvn clean package``

<b>2. Deploy to Azure:</b>


``mvn azure-functions:deploy``

<b>To run locally:</b>
``mvn azure-functions:run``
