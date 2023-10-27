package io.mosip.registration.processor.packet.receiver.stage;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.util.ClassUtils;

import com.hazelcast.config.Config;
import com.hazelcast.config.UrlXmlConfig;

import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.registration.processor.core.abstractverticle.MessageBusAddress;
import io.mosip.registration.processor.core.abstractverticle.MessageDTO;
import io.mosip.registration.processor.core.abstractverticle.MosipEventBus;
import io.mosip.registration.processor.core.abstractverticle.MosipRouter;
import io.mosip.registration.processor.core.abstractverticle.MosipVerticleAPIManager;
import io.mosip.registration.processor.core.constant.LoggerFileConstant;
import io.mosip.registration.processor.core.eventbus.MosipEventBusFactory;
import io.mosip.registration.processor.core.exception.DeploymentFailureException;
import io.mosip.registration.processor.core.exception.UnsupportedEventBusTypeException;
import io.mosip.registration.processor.core.exception.util.PlatformErrorMessages;
import io.mosip.registration.processor.core.logger.RegProcessorLogger;
import io.mosip.registration.processor.core.status.util.StatusUtil;
import io.mosip.registration.processor.packet.manager.exception.systemexception.UnexpectedException;
import io.mosip.registration.processor.packet.receiver.builder.PacketReceiverResponseBuilder;
import io.mosip.registration.processor.packet.receiver.dto.PacketReceiverResponseDTO;
import io.mosip.registration.processor.packet.receiver.exception.PacketReceiverAppException;
import io.mosip.registration.processor.packet.receiver.exception.handler.PacketReceiverExceptionHandler;
import io.mosip.registration.processor.packet.receiver.service.PacketReceiverService;
import io.vertx.core.DeploymentOptions;
import io.vertx.core.Verticle;
import io.vertx.core.Vertx;
import io.vertx.core.VertxOptions;
import io.vertx.core.eventbus.EventBusOptions;
import io.vertx.core.spi.cluster.ClusterManager;
import io.vertx.ext.web.FileUpload;
import io.vertx.ext.web.RoutingContext;
import io.vertx.micrometer.MicrometerMetricsOptions;
import io.vertx.micrometer.VertxPrometheusOptions;
import io.vertx.spi.cluster.hazelcast.HazelcastClusterManager;

/**
 * The Class PacketReceiverStage.
 */

@RefreshScope
@Service
@Configuration
@ComponentScan(basePackages = { "${mosip.auth.adapter.impl.basepackage}",
		  "io.mosip.registration.processor.status.config",
		  "io.mosip.registration.processor.packet.receiver.config",
		  "io.mosip.registration.processor.core.config",
		  "io.mosip.registration.processor.rest.client.config" })
public class PacketReceiverStage extends MosipVerticleAPIManager {

	/** The reg proc logger. */
	private static Logger regProcLogger = RegProcessorLogger.getLogger(PacketReceiverStage.class);

	private static final String STAGE_PROPERTY_PREFIX = "mosip.regproc.packet.receiver.";

	/** vertx Cluster Manager Url. */
	@Value("${vertx.cluster.configuration}")
	private String clusterManagerUrl="http://localhost:51000/registration-processor/local/master/hazelcast_default.xml";

	/** worker pool size. */
	@Value("${worker.pool.size}")
	private Integer workerPoolSize=30;

	/** The Constant DATETIME_PATTERN. */
	private static final String DATETIME_PATTERN = "mosip.registration.processor.datetime.pattern";

	/** The Constant APPLICATION_VERSION. */
	private static final String APPLICATION_VERSION = "mosip.registration.processor.application.version";

	/** The Constant MODULE_ID. */
	private static final String MODULE_ID = "mosip.registration.processor.packet.id";

	/** The Constant APPLICATION_JSON. */
	private static final String APPLICATION_JSON = "application/json";

	/** The Packet Receiver Service. */
	@Autowired
	public PacketReceiverService<File, MessageDTO> packetReceiverService;

	/** Exception handler. */
	@Autowired
	public PacketReceiverExceptionHandler globalExceptionHandler;

	/** The packet receiver response builder. */
	@Autowired
	PacketReceiverResponseBuilder packetReceiverResponseBuilder;

	/**
	 * The mosip event bus.
	 */
	private MosipEventBus mosipEventBus;

	/**  Mosip router for APIs. */
	@Autowired
	MosipRouter router;

	/**
	 * deploys this verticle.
	 */
	public void deployVerticle() {
		this.mosipEventBus = this.getEventBus(this, clusterManagerUrl, workerPoolSize);
	}

	/** The env. */
	@Autowired
	private Environment env;

	@Autowired
	private MosipEventBusFactory mosipEventBusFactory;
	/*
	 * (non-Javadoc)
	 *
	 * @see io.vertx.core.AbstractVerticle#start()
	 */
	@Override
	public void start() {
		router.setRoute(this.postUrl(vertx, null, MessageBusAddress.PACKET_RECEIVER_OUT));
		this.routes(router);
		this.createServer(router.getRouter(), getPort());
	}

	/**
	 * contains all the routes in the stage.
	 *
	 * @param router
	 *            the router
	 */
	private void routes(MosipRouter router) {

		router.post(getServletPath() + "/registrationpackets");
		router.handler(this::processURL, this::processPacket, this::failure);
	};

	/**
	 * This is for failure handler.
	 *
	 * @param routingContext the routing context
	 */
	public void failure(RoutingContext routingContext) {
		try {
			Entry<FileUpload,File> fileUploadEntry=getFileFromCtx(routingContext).entrySet().iterator().next();
			File file = fileUploadEntry.getValue();
			regProcLogger.error("Exception occurred for packet id : " + file.getName(), routingContext.failure());
			deleteFile(file);
			deleteFile(FileUtils.getFile(fileUploadEntry.getKey().uploadedFileName()));
		} catch (IOException e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					"", e.getMessage() + ExceptionUtils.getStackTrace(e));
		}
		this.setResponseWithDigitalSignature(routingContext, globalExceptionHandler.handler(routingContext.failure()),
				APPLICATION_JSON);
	}


	/**
	 * Process packet.
	 *
	 * @param ctx the ctx
	 */
	public void processPacket(RoutingContext ctx) {
		File file=null;
		File temporaryFile=null;
		try {
			regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					"", "PacketReceiverStage::processPacket()::entry");
			Entry<FileUpload,File> fileUploadEntry=getFileFromCtx(ctx).entrySet().iterator().next();
			file=fileUploadEntry.getValue();
			temporaryFile=FileUtils.getFile(fileUploadEntry.getKey().uploadedFileName());
			MessageDTO messageDTO = packetReceiverService.processPacket(file);
			messageDTO.setMessageBusAddress(MessageBusAddress.PACKET_RECEIVER_OUT);
			if (messageDTO.getIsValid()) {
				this.sendMessage(messageDTO);
			}
		} catch (IOException e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					"", e.getMessage() + ExceptionUtils.getStackTrace(e));
			throw new UnexpectedException(e.getMessage());
		} finally {
			deleteFile(file);
			deleteFile(temporaryFile);
		}
		regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
				"", "PacketReceiverStage::processPacket()::exit");

	}

	/**
	 * contains process logic for the context passed.
	 *
	 * @param ctx            the ctx
	 * @throws PacketReceiverAppException the packet receiver app exception
	 */
	public void processURL(RoutingContext ctx) throws PacketReceiverAppException {

		try {
			regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					"", "PacketReceiverStage::processURL()::entry");
			List<String> listObj = new ArrayList<>();
			listObj.add(env.getProperty(MODULE_ID));
			File file=getFileFromCtx(ctx).entrySet().iterator().next().getValue();
			MessageDTO messageDTO = packetReceiverService.validatePacket(file, getStageName());
			listObj.add(DateUtils.getUTCCurrentDateTimeString(env.getProperty(DATETIME_PATTERN)));
			listObj.add(env.getProperty(APPLICATION_VERSION));
			if (messageDTO.getIsValid()) {
				PacketReceiverResponseDTO responseData=PacketReceiverResponseBuilder.buildPacketReceiverResponse(StatusUtil.PACKET_RECEIVED.getMessage(), listObj);
				this.setResponseWithDigitalSignature(ctx, responseData, APPLICATION_JSON);
			}
		} catch (IOException e) {
			regProcLogger.error(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
					"", e.getMessage() + ExceptionUtils.getStackTrace(e));
			throw new UnexpectedException(e.getMessage());
		}
		regProcLogger.debug(LoggerFileConstant.SESSIONID.toString(), LoggerFileConstant.REGISTRATIONID.toString(),
				"", "PacketReceiverStage::processURL()::exit");
		ctx.next();
	}

	/**
	 * deletes a file.
	 *
	 * @param file
	 *            the file
	 */
	public void deleteFile(File file) {
		try {
			if (file != null) {
				if (file.exists()) {
					FileUtils.forceDelete(file);
				}
			}
		} catch (IOException e) {
			throw new UnexpectedException(e.getMessage());
		}
	}

	/**
	 * sends messageDTO to camel bridge.
	 *
	 * @param messageDTO
	 *            the message DTO
	 */
	public void sendMessage(MessageDTO messageDTO) {
		this.send(this.mosipEventBus, MessageBusAddress.PACKET_RECEIVER_OUT, messageDTO);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * io.mosip.registration.processor.core.spi.eventbus.EventBusManager#process(
	 * java.lang.Object)
	 */
	@Override
	public MessageDTO process(MessageDTO object) {
		return null;
	}

	@Override
	protected String getPropertyPrefix() {
		return STAGE_PROPERTY_PREFIX;
	}

	/**
	 * Gets the file from ctx.
	 *
	 * @param ctx the ctx
	 * @return the file from ctx
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private Map<FileUpload,File> getFileFromCtx(RoutingContext ctx) throws IOException {
		FileUpload fileUpload = ctx.fileUploads().iterator().next();
		FileUtils.copyFile(FileUtils.getFile(fileUpload.uploadedFileName()),
				FileUtils.getFile(FileUtils.getFile(fileUpload.uploadedFileName()).getParent() + "/" + fileUpload.fileName()));
		File file = FileUtils.getFile(FileUtils.getFile(fileUpload.uploadedFileName()).getParent() + "/" + fileUpload.fileName());
		Map<FileUpload,File> uploadedFileMap=new HashMap<>();
		uploadedFileMap.put(fileUpload,file);
		return uploadedFileMap;

	}
	
	public MosipEventBus getEventBus(Object verticleName, String clusterManagerUrl, int instanceNumber) {
		CompletableFuture<Vertx> eventBus = new CompletableFuture<>();
		MosipEventBus mosipEventBus = null;
		Config config;
		try {
			config = new UrlXmlConfig(clusterManagerUrl);
		} catch (IOException e1) {
			throw new DeploymentFailureException(PlatformErrorMessages.RPR_CMB_MALFORMED_URL_EXCEPTION.getMessage());
		}
		ClusterManager clusterManager = new HazelcastClusterManager(config);
		String address = null;
		try {
			address = InetAddress.getLocalHost().getHostAddress();
		} catch (UnknownHostException e1) {
			throw new DeploymentFailureException(PlatformErrorMessages.RPR_CMB_MALFORMED_URL_EXCEPTION.getMessage());
		}

		MicrometerMetricsOptions micrometerMetricsOptions = new MicrometerMetricsOptions()
				.setPrometheusOptions(new VertxPrometheusOptions()
						.setEnabled(true))
				.setEnabled(true);

		VertxOptions options = new VertxOptions().setClustered(true).setClusterManager(clusterManager)
				.setHAEnabled(false).setWorkerPoolSize(instanceNumber)
				.setEventBusOptions(new EventBusOptions().setPort(5711).setHost(address))
				.setMetricsOptions(micrometerMetricsOptions);
		Vertx.clusteredVertx(options, result -> {
			if (result.succeeded()) {
				result.result().deployVerticle((Verticle) verticleName,
						new DeploymentOptions().setHa(false).setWorker(true).setWorkerPoolSize(instanceNumber));
				eventBus.complete(result.result());
//				logger.debug(verticleName + " deployed successfully");
			} else {
				throw new DeploymentFailureException(PlatformErrorMessages.RPR_CMB_DEPLOYMENT_FAILURE.getMessage());
			}
		});

		try {
			Vertx vert = eventBus.get();
			mosipEventBus = mosipEventBusFactory.getEventBus(vert, getEventBusType(), getPropertyPrefix());
		} catch (InterruptedException | ExecutionException | UnsupportedEventBusTypeException e) {
			Thread.currentThread().interrupt();
			throw new DeploymentFailureException(PlatformErrorMessages.RPR_CMB_DEPLOYMENT_FAILURE.getMessage(), e);
		}
		return mosipEventBus;
	}
}
