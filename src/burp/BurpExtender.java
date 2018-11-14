package burp;

import java.util.HashSet;
import java.util.Set;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JOptionPane;

/**
 *
 * @author jamesjardine
 */
public class BurpExtender implements IBurpExtender, IScannerCheck, IHttpListener
{
    IBurpExtenderCallbacks callbacks = null;
    private IExtensionHelpers helpers;
    
    
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        
        callbacks.setExtensionName("Exception Finder");
        
        callbacks.registerScannerCheck(this);
        callbacks.registerHttpListener(this);
        System.out.println("Loaded");
    }
    
    // This method will look for the existence of the Exception and 
    // return the start and end position of the entire object.
    private List<int[]> getMatches(byte[] response)
    {
        
        byte[] startString = "Exception".getBytes();
        List<int[]> matches = new ArrayList<int[]>();
        
        int start = 0;

        start = helpers.indexOf(response,startString,true,start,response.length);
        
        // Check to see if we found Exception in the response.
        if(start > -1)
        {
            int end = start + 9;
            matches.add(new int[] {start,end });
        }
        
        return matches;
    }
    
    @Override
    public void processHttpMessage(int toolId, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if(!messageIsRequest && toolId == 64)
        {
            // Repeater is being used and it is a response.  Process the message.
            List<int[]> matches = getMatches(messageInfo.getResponse());
        
            // If Exception is found, pop an alert box.
            if(matches.size() > 0)
            {
                JOptionPane.showMessageDialog(null,"Exception Message Found","Warning",JOptionPane.WARNING_MESSAGE);
            }
        }
    }
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        // Determine if we identify the Exception
        List<int[]> matches = getMatches(baseRequestResponse.getResponse());
        
        // If Exception is found create the scanner issue.
        if(matches.size() > 0)
        {
            // Create a new scan issue.
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
            baseRequestResponse.getHttpService(),
            helpers.analyzeRequest(baseRequestResponse).getUrl(),
            new IHttpRequestResponse[]{ callbacks.applyMarkers(baseRequestResponse,null,matches)},
            "Exception Detected",
            "The Response contains the string: Exception",
            "Information"));
            return issues;
        }
        else return null;
    }
    
        @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        // We are not implementing this for Active Scan at this time. 
        // As an extra challenge, implement this function.
        return null;
    }
    
        @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // There should only be one issue created by this plugin. If the scanner 
        // identifies it again, just ignore it.
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}

class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
}
