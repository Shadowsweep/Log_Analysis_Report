
### Log analysis Report 

## The tasks we had Completed in this script are -
1. To parse the log file and idetify the status codes used ,the    endpoints accessed in our sample.log file.
2. After that we search the string and extract spcific parts and used .group to get powerful extraction we need .
3. After that we implemented most common so that we can get the highest no. of the times the endpoints which has been acessed 
4. And then we converted the code and returned in csv file


## Apart from assisment i had tried to test for suspicious activity 
1. after that saved the report in test_log_analysis.csv with terminal printing 





### Step-by-Step Process
1. Read the log file line by line
2. Extract important information from each log entry
3. Count and categorize website activities
4. Generate a comprehensive report
5. Save the report as a CSV file

## 📝 Example
```
Imagine you run a website:
- The script reads your log file
- It tells you:
  * Most visited page: "/login"
  * Most active IP: "192.168.1.100"
  * Suspicious attempts: 15 failed logins from "123.45.67.89"
```

## 🚀 Quick Start
1. Save the script
2. Point it to your log file
3. Run and get instant insights of the site

### Information Extracted
- IP addresses of visitors
- Requested web pages
- HTTP methods used (GET, POST, etc.)
- Status of each request
- Login attempt details

## 🔧 Easy Customization
- Change the number of failed attempts that trigger a "suspicious" flag
- Modify input and output file paths
- Adjust the analysis to fit your specific needs

## 🛡️ Security Insights
- Quickly identify potential security threats
- Track unauthorized access attempts
- Monitor login failure patterns

