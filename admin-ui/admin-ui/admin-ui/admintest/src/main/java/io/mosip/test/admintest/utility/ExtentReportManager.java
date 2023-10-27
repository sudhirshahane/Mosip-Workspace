package io.mosip.test.admintest.utility;

import com.aventstack.extentreports.ExtentReports;
import com.aventstack.extentreports.ExtentTest;

import com.aventstack.extentreports.reporter.ExtentSparkReporter;

public class ExtentReportManager {
	public static ExtentSparkReporter html;
	public static	ExtentReports extent;
	//public static WebDriver driver;
	public static	ExtentTest test;
	public static ExtentReports getReports() {
		if(extent==null) {
			extent=new ExtentReports();
			extent=new ExtentReports();
			String path=System.getProperty("user.dir")+"/Reports/"+"AdminReports"+Commons.getDateTime()+".html";
			html=new ExtentSparkReporter(path);
			  extent.attachReporter(html);
		}
		
		return extent;
		
	}
}
