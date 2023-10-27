package io.mosip.test.admintest.utility;

import java.util.List;

import org.testng.TestListenerAdapter;
import org.testng.TestNG;

import io.mosip.test.admintest.testcase.*;


public class TestRunner {
	static TestListenerAdapter tla = new TestListenerAdapter();

	
	static TestNG testNg;
	
	public static void main(String[] args) throws Exception {
	
		testNg=new TestNG();
		
		String listExcludedGroups=JsonUtil.JsonObjParsing(Commons.getTestData(),"setExcludedGroups");
		testNg.setExcludedGroups(listExcludedGroups);
		testNg.setTestClasses(new Class[] {
				
	CenterTest.class,HolidaysTest.class,TemplateTest.class
				
				,
				
				DeviceTest.class,MachineTest.class
				,BlockListTest.class,CenterTypeTest.class,
				DeviceSpecificationTest.class,DeviceTypesTest.class,
				MachineSpecificationTest.class,MachineTypesTest.class,
				DynamicFieldTest.class,DocumentCategoriesTest.class,DocumentTypes.class,
				
			BulkUploadTest.class
		
		});
	//	testNg.addListener(tla);
		testNg.run();
		
	}
	

}
