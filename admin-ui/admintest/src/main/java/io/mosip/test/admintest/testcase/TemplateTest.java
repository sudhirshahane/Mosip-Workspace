package io.mosip.test.admintest.testcase;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.openqa.selenium.By;
import org.openqa.selenium.Dimension;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.StaleElementReferenceException;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.interactions.Actions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
// Generated by Selenium IDE
//import org.junit.Test;
//import org.junit.Before;
//import org.junit.After;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import io.mosip.test.admintest.utility.BaseClass;
import io.mosip.test.admintest.utility.Commons;

public class TemplateTest extends BaseClass{
 
 
  @Test(groups = "T")
  public void templateCRUD() {
	  String templatesid="admin/masterdata/templates/view";
	  
    Commons.click(driver,By.xpath("//a[@href='#/admin/masterdata']"));
   
    Commons.click(driver,By.id(templatesid));
    Commons.click(driver,By.id("Create"));
  
    Commons.enter(driver,By.id("name"),data);
    Commons.enter(driver,By.id("description"),data);

    Commons.enter(driver,By.id("model"),data);
    Commons.enter(driver,By.id("fileText"),data);


    Commons.dropdown(driver,By.id("fileFormatCode"));
  
    Commons.dropdown(driver,By.id("templateTypeCode"));
    
    Commons.dropdown(driver,By.id("moduleId"));
    

    

    Commons.create(driver);
	Commons.filter(driver, By.id("name"), data);
	

	Commons.edit(driver,data+1,By.id("name"));
	Commons.filter(driver, By.id("name"), data+1);
	
	Commons.activate(driver);
	Commons.edit(driver,data+2,By.id("name"));
	Commons.filter(driver, By.id("name"), data+2);
	Commons.deactivate(driver);


  }
}
