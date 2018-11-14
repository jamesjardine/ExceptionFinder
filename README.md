# ExceptionFinder
Simple Burp plugin to identify exceptions in a response.

This project is just a sample to show how a simple burp extension can be created to help identify specific information. In this case, the tool simply identifies if a response contains the word "Exception". 

## Use
The extension is easy to use, however because it uses the passive scanner it does require the commercial version of Burp Suite. Build the Jar file and then in Burp open up the Extender tab. Next, select the Add button and select your new JAR file. Visit the Juice Shop application and click the Target Tab in Burp. Find the Juice Shop URL in the left and select it. Then, click on the Issue tab and look for the Angular Routes issue. Viewing the description should show you the routes within the application.
