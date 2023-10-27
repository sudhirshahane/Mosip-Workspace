package org.biometric.provider;

import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.imageio.ImageIO;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.registration.mdm.dto.StreamingRequestDetail;

public class StreamRequest extends HttpServlet {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1914160572219233317L;
	ObjectMapper oB = null;


	@Override
    protected void service(HttpServletRequest req, HttpServletResponse res)
            throws ServletException, IOException {
        //if(req.getMethod().contentEquals("STREAM"))
        if(req.getMethod().contentEquals("STREAM") || req.getMethod().contentEquals("POST") || req.getMethod().contentEquals("GET"))
            doPost(req, res);
        if(req.getMethod().contentEquals("OPTIONS"))
            CORSManager.doOptions(req, res);
        //if(req.getMethod().contentEquals("GET"))
		//	CORSManager.doOptions(req, res);
    }



	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		if(oB==null)
			oB = new ObjectMapper();

		List<byte[]> imageByteList = null;
		response.setContentType("multipart/x-mixed-replace; boundary=--BoundaryString");
		response = CORSManager.setCors(response);
		BufferedReader bR = request.getReader();
		String s="";
		String sT = "";
		while((s = bR.readLine())!=null) {
			sT = sT+s;
		}

		if(sT.isEmpty())
		{
			String devId = null;
			String devSubId = null;
			if(request.getMethod().equals("GET"))
			{
				devId = request.getParameter("deviceId");
				devSubId = request.getParameter("deviceSubId");
			}
			sT = "{\"deviceId\": \"" 
			+ (devId != null?devId:"")
			+ "\", \"deviceSubId\": \""
			+ (devSubId != null?devSubId:"")
			+ "\"}";
		}
		StreamingRequestDetail streamRequest = (StreamingRequestDetail)(oB.readValue(sT.getBytes(), StreamingRequestDetail.class));
		imageByteList = new ArrayList<byte[]>();
		OutputStream outputStream = response.getOutputStream();
	
		getImage(streamRequest, imageByteList);
		getImage(imageByteList);

		int i = 0;
		while (true) {
			try {
				outputStream.write(("--BoundaryString\r\n" + "Content-type: image/jpeg\r\n" + "Content-Length: "
						+ imageByteList.get(i).length + "\r\n\r\n").getBytes());
				outputStream.write(imageByteList.get(i));
				outputStream.write("\r\n\r\n".getBytes());
				outputStream.flush();
				if (i == 0)
					i = 1;
				else if (i == 1)
					i = 0;
				TimeUnit.MILLISECONDS.sleep(3000);
			} catch (Exception e) {
				return;
			}
		}
	}

	
	private void getImage(StreamingRequestDetail requestBody, List<byte[]> imageByteList) throws IOException {

		File image = new File(System.getProperty("user.dir") + "/files/images/stream" + requestBody.deviceId
				+ requestBody.deviceSubId + ".jpg");
		BufferedImage originalImage = ImageIO.read(image);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(originalImage, "jpg", baos);
		baos.flush();
		imageByteList.add(baos.toByteArray());
	}

	private void getImage(List<byte[]> imageByteList) throws IOException {

		File image = new File(System.getProperty("user.dir") + "/files/images/" + "stream30" + ".jpg");
		BufferedImage originalImage = ImageIO.read(image);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ImageIO.write(originalImage, "jpg", baos);
		baos.flush();
		imageByteList.add(baos.toByteArray());
	}
	
}
