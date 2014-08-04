/*
 * Copyright 2014 Hana Lab. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.uci.hana.visualizer;

import com.google.api.client.auth.oauth2.TokenResponseException;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.client.util.DateTime;
import com.google.api.client.util.IOUtils;
import com.google.api.services.plus.Plus;
import com.google.api.services.plus.model.PeopleFeed;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.log4j.BasicConfigurator;
import org.eclipse.jetty.util.log.Log;
import org.mortbay.jetty.Server;
import org.mortbay.jetty.servlet.ServletHandler;
import org.mortbay.jetty.servlet.SessionHandler;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Scanner;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.api.services.drive.Drive;
import com.google.api.services.drive.model.Revision;
import com.google.api.services.drive.model.RevisionList;

import edu.uci.hana.visualizer.diff_match_patch.Diff;
import edu.uci.hana.visualizer.diff_match_patch.LinesToCharsResult;
import edu.uci.hana.visualizer.diff_match_patch.Operation;

/**
 * Hana Lab Visualizer program to visualize Google Drive Documents History Flow.
 * 
 * Based on the sample code Google+ Sign-In by joannasmith@google.com (Joanna
 * Smith) vicfryzel@google.com (Vic Fryzel)
 * 
 * @author dakuow1@uci.edu (Dakuo Wang) since Jan 29, 2014
 * @advisor Judith Olson
 * @advisor Crista Lopes 
 * 
 * Dev Log: Feb 1, 2014 Added Polling Javascript function
 *          and Servlet handler 
 *          Feb 5, 2014 Added Diff algorithm (beta)
 * 			Jul 21, 2014 Added Movement Detection algorithm feature
 */
public class Visualizer {
	/*
	 * Default HTTP transport to use to make HTTP requests.
	 */
	private static final HttpTransport TRANSPORT = new NetHttpTransport();

	/*
	 * Default JSON factory to use to deserialize JSON.
	 */
	private static final JacksonFactory JSON_FACTORY = new JacksonFactory();

	/*
	 * Gson object to serialize JSON responses to requests to this servlet.
	 */

	private static final Gson GSON;

	/*
	 * Creates a client secrets object from the client_secrets.json file.
	 */
	private static GoogleClientSecrets clientSecrets;

	/*
	 * Create a Downloading In Progress Doc Index List from the
	 * downloadingList.txt Create a Done Downloaded Doc Index List from the
	 * downloadedList.txt
	 */
	private static final File downloadingListFile;
	private static final HashMap<String, Integer> downloadingList;

	private static final File downloadedListFile;
	private static final HashMap<String, String> downloadedList;

	/*
	 * Create a Diff-ing In Progress Doc Index List from the diffingList.txt
	 * Create a Done Diff Doc Index List from the diffedList.txt
	 */
	private static final File diffingListFile;
	private static final HashMap<String, Integer> diffingList;

	private static final File diffedListFile;
	private static final HashMap<String, String> diffedList;

	// Folder Path to save downloaded revision files (docId/revisionId_time) and
	// the index (list.txt) file
	// and the intermediate data (historyflow.json) file
	private static final String revisionFileDir;

	// diff patch match object
	private static final diff_match_patch DMP;

	// time zone
	private static final SimpleDateFormat PST;

	static {
		try {
			PST = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
			PST.setTimeZone(TimeZone.getTimeZone("PST"));

			DMP = new diff_match_patch();
			DMP.Diff_Timeout = 1;

			GSON = new GsonBuilder().excludeFieldsWithoutExposeAnnotation()
					.create();

			Reader reader = new FileReader("client_secrets.json");
			clientSecrets = GoogleClientSecrets.load(JSON_FACTORY, reader);
			reader.close();

			downloadingListFile = new File("downloadingList.txt");
			downloadingList = new HashMap<String, Integer>();
			downloadedListFile = new File("downloadedList.txt");
			downloadedList = new HashMap<String, String>();

			diffingListFile = new File("diffingList.txt");
			diffingList = new HashMap<String, Integer>();
			diffedListFile = new File("diffedList.txt");
			diffedList = new HashMap<String, String>();

			BufferedReader br = new BufferedReader(new FileReader(
					"downloadingList.txt"));
			String line = br.readLine();
			while (line != null) {
				String[] docListPair = line.split(":", 2);
				downloadingList.put(docListPair[0],
						Integer.valueOf(docListPair[1]));
				line = br.readLine();
			}
			br.close();

			BufferedReader br1 = new BufferedReader(new FileReader(
					downloadedListFile));
			line = br1.readLine();
			while (line != null) {
				String[] docListPair = line.split(":", 2);
				downloadedList.put(docListPair[0], docListPair[1]);
				line = br1.readLine();
			}
			br1.close();

			BufferedReader br2 = new BufferedReader(new FileReader(
					diffingListFile));
			line = br2.readLine();
			while (line != null) {
				String[] docListPair = line.split(":", 2);
				diffingList
						.put(docListPair[0], Integer.valueOf(docListPair[1]));
				line = br2.readLine();
			}
			br2.close();

			BufferedReader br3 = new BufferedReader(new FileReader(
					diffedListFile));
			line = br3.readLine();

			while (line != null) {
				String[] docListPair = line.split(":", 2);
				diffedList.put(docListPair[0], docListPair[1]);
				line = br3.readLine();
			}

			br3.close();

			revisionFileDir = "fileDB/";

		} catch (IOException e) {
			throw new Error(
					"No client_secrets.json OR other initializing files (Four ing-ed list files) found",
					e);
		}
	}

	/*
	 * This is the Client ID that you generated in the API Console.
	 */
	private static final String CLIENT_ID = clientSecrets.getWeb()
			.getClientId();

	/*
	 * This is the Client Secret that you generated in the API Console.
	 */
	private static final String CLIENT_SECRET = clientSecrets.getWeb()
			.getClientSecret();

	/*
	 * Optionally replace this with your application's name.
	 */
	private static final String APPLICATION_NAME = "Hana Viz";

	/**
	 * Register all endpoints that we'll handle in our server.
	 * 
	 * @param args
	 *            Command-line arguments.
	 * @throws Exception
	 *             from Jetty if the component fails to start
	 */
	public static void main(String[] args) throws Exception {
		BasicConfigurator.configure();
		Server server = new Server(4567);
		ServletHandler servletHandler = new ServletHandler();
		SessionHandler sessionHandler = new SessionHandler();
		sessionHandler.setHandler(servletHandler);
		server.setHandler(sessionHandler);
		
		// handler for request saving the svg to a jpeg image 
		servletHandler.addServletWithMapping(SaveImageServlet.class, "/saveImage");
		
		// handler for request asking for single segment content
		servletHandler.addServletWithMapping(SegmentServlet.class, "/seg");
		
		// handler for request changing segment's author
		servletHandler.addServletWithMapping(ChangeSegmentAuthorServlet.class, "/segAuthor");

		// Visualize the intermediate data generated by diff
		servletHandler.addServletWithMapping(VisualizeServlet.class, "/viz");

		// TODO May not need it if we diff revisions while we are downloading
		// revisions
		servletHandler.addServletWithMapping(DiffRevisionsServlet.class,
				"/diffrevisions");
		// handler for polling request to check downloading / diffing tasks
		servletHandler.addServletWithMapping(PollingServlet.class, "/polling");
		// handler for using Google Drive API to download the revisions document
		servletHandler.addServletWithMapping(RevisionsServlet.class,
				"/revisions");
		servletHandler.addServletWithMapping(ConnectServlet.class, "/connect");
		servletHandler.addServletWithMapping(DisconnectServlet.class,
				"/disconnect");
		// TODO no use, could be deleted after all
		servletHandler.addServletWithMapping(PeopleServlet.class, "/people");

		servletHandler.addServletWithMapping(MainServlet.class, "/");
		server.start();
		server.join();
	}

	/**
	 * Initialize a session for the current user, and render index.html.
	 */
	public static class MainServlet extends HttpServlet {

		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			// This check prevents the "/" handler from handling all requests by
			// default
			if (!"/".equals(request.getServletPath())) {
				response.setStatus(HttpServletResponse.SC_NOT_FOUND);
				return;
			}

			response.setContentType("text/html");
			try {
				// Create a state token to prevent request forgery.
				// Store it in the session for later validation.
				String state = new BigInteger(130, new SecureRandom())
						.toString(32);
				request.getSession().setAttribute("state", state);
				// Fancy way to read index.html into memory, and set the client
				// ID
				// and state values in the HTML before serving it.
				response.getWriter().print(
						new Scanner(new File("index.html"), "UTF-8")
								.useDelimiter("\\A")
								.next()
								.replaceAll("[{]{2}\\s*CLIENT_ID\\s*[}]{2}",
										CLIENT_ID)
								.replaceAll("[{]{2}\\s*STATE\\s*[}]{2}", state)
								.replaceAll(
										"[{]{2}\\s*APPLICATION_NAME\\s*[}]{2}",
										APPLICATION_NAME).toString());
				response.setStatus(HttpServletResponse.SC_OK);
			} catch (FileNotFoundException e) {
				// When running the quickstart, there was some path issue in
				// finding
				// index.html. Double check the quickstart guide.
				e.printStackTrace();
				response.setStatus(HttpServletResponse.SC_NOT_FOUND);
				response.getWriter().print(e.toString());
			}
		}
	}

	/**
	 * Upgrade given auth code to token, and store it in the session. POST body
	 * of request should be the authorization code. Example URI:
	 * /connect?state=...&gplus_id=...
	 */
	public static class ConnectServlet extends HttpServlet {
		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			// Only connect a user that is not already connected.
			String tokenData = (String) request.getSession().getAttribute(
					"token");
			/*
			if (tokenData != null) {
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().print(
						GSON.toJson("Current user is already connected."));
				return;
			}
			*/
			
			// Ensure that this is no request forgery going on, and that the
			// user
			// sending us this connect request is the user that was supposed to.
			if (!request.getParameter("state").equals(
					request.getSession().getAttribute("state"))) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Invalid state parameter."));
				return;
			}
			// Normally the state would be a one-time use token, however in our
			// simple case, we want a user to be able to connect and disconnect
			// without reloading the page. Thus, for demonstration, we don't
			// implement this best practice.
			//request.getSession().removeAttribute("state");

			ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
			getContent(request.getInputStream(), resultStream);
			String code = new String(resultStream.toByteArray(), "UTF-8");

			try {
				// Upgrade the authorization code into an access and refresh
				// token.
				GoogleTokenResponse tokenResponse = new GoogleAuthorizationCodeTokenRequest(
						TRANSPORT, JSON_FACTORY, CLIENT_ID, CLIENT_SECRET,
						code, "postmessage").execute();

				// You can read the Google user ID in the ID token.
				// This sample does not use the user ID.
				//TODO this can be deleted, sample code
				//GoogleIdToken idToken = tokenResponse.parseIdToken();
				//String gplusId = idToken.getPayload().getSubject();

				// Store the token in the session for later use.
				request.getSession().setAttribute("token",
						tokenResponse.toString());
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().print(
						GSON.toJson("Successfully connected user."));
			} catch (TokenResponseException e) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter()
						.print(GSON
								.toJson("Failed to upgrade the authorization code."));
			} catch (IOException e) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Failed to read token data from Google. "
								+ e.getMessage()));
			}
		}

		/**
		 * Read the content of an InputStream.
		 * 
		 * @param inputStream
		 *            the InputStream to be read.
		 * 
		 * @return the content of the InputStream as a ByteArrayOutputStream.
		 * 
		 * @throws IOException
		 */
		static void getContent(InputStream inputStream,
				ByteArrayOutputStream outputStream) throws IOException {
			// Read the response into a buffered stream
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					inputStream));
			int readChar;
			while ((readChar = reader.read()) != -1) {
				outputStream.write(readChar);
			}
			reader.close();
		}
	}

	/**
	 * Revoke current user's token and reset their session.
	 */
	public static class DisconnectServlet extends HttpServlet {
		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			// Only disconnect a connected user.
			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
			try {
				// Build credential from stored token data.
				GoogleCredential credential = new GoogleCredential.Builder()
						.setJsonFactory(JSON_FACTORY)
						.setTransport(TRANSPORT)
						.setClientSecrets(CLIENT_ID, CLIENT_SECRET)
						.build()
						.setFromTokenResponse(
								JSON_FACTORY.fromString(tokenData,
										GoogleTokenResponse.class));
				// Execute HTTP GET request to revoke current token.
				HttpResponse revokeResponse = TRANSPORT
						.createRequestFactory()
						.buildGetRequest(
								new GenericUrl(
										String.format(
												"https://accounts.google.com/o/oauth2/revoke?token=%s",
												credential.getAccessToken())))
						.execute();
				// Reset the user's session.
				request.getSession().removeAttribute("token");
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().print(
						GSON.toJson("Successfully disconnected."));
			} catch (IOException e) {
				// For whatever reason, the given token was invalid.
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Failed to revoke token for given user."));
			}
		}
	}

	/**
	 * Get list of people user has shared with this app.
	 */
	public static class PeopleServlet extends HttpServlet {
		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			// Only fetch a list of people for connected users.
			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
			try {
				// Build credential from stored token data.
				GoogleCredential credential = new GoogleCredential.Builder()
						.setJsonFactory(JSON_FACTORY)
						.setTransport(TRANSPORT)
						.setClientSecrets(CLIENT_ID, CLIENT_SECRET)
						.build()
						.setFromTokenResponse(
								JSON_FACTORY.fromString(tokenData,
										GoogleTokenResponse.class));
				// Create a new authorized API client.
				Plus service = new Plus.Builder(TRANSPORT, JSON_FACTORY,
						credential).setApplicationName(APPLICATION_NAME)
						.build();
				// Get a list of people that this user has shared with this app.
				PeopleFeed people = service.people().list("me", "visible")
						.execute();
				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().print(GSON.toJson(people));
			} catch (IOException e) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Failed to read data from Google. "
								+ e.getMessage()));
			}
		}
	}

	/**
	 * 
	 * The start-point for the visualization chain.
	 */
	public static class RevisionsServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			// Only fetch a list of people for connected users.
			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("In RevisionServlet. Current user not connected."));
				return;
			}
			if (request.getParameter("doc_id") == null) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Document Id not provided."));
				return;
			}
			/*
			 * search for the diff-ed and diff-ing list 
			 * and download-ed and download-ing list to see whether
			 * we need to initiate a new API call and downloading process
			 */
			if (diffedList.containsKey(request.getParameter("doc_id"))) {
				//the last time we diffed the file in system
				String vizTime = diffedList.get(request.getParameter("doc_id"));
				
				//check if the update time which we get from Google equals to this one
				try {
					// Build credential from stored token data.
					GoogleCredential credential = new GoogleCredential.Builder()
							.setJsonFactory(JSON_FACTORY)
							.setTransport(TRANSPORT)
							.setClientSecrets(CLIENT_ID, CLIENT_SECRET)
							.build()
							.setFromTokenResponse(
									JSON_FACTORY.fromString(tokenData,
											GoogleTokenResponse.class));
					// Create a new authorized API client.
					Drive service = new Drive.Builder(TRANSPORT, JSON_FACTORY,
							credential).setApplicationName(APPLICATION_NAME)
							.build();

					// Get a list of revisions .
					com.google.api.services.drive.model.File file = service.files().get(request.getParameter("doc_id")).setFields("modifiedDate")
							.execute();
					String updateTime = PST.format(new Date(file.getModifiedDate().getValue()));
					// subtract the milsecond in order to simplify the comparison 
					updateTime =  updateTime.split("\\.")[0]+".000";
					vizTime = vizTime.split("\\.")[0]+".000";
					
					// update after we visualized last time
					if( DateTime.parseRfc3339(updateTime).getValue() == DateTime.parseRfc3339(vizTime).getValue()) 
					{
						
						response.setStatus(HttpServletResponse.SC_ACCEPTED);
						response.getWriter().print(
								GSON.toJson("The Document "
										+ request.getParameter("doc_name")
										+ " has been downloaded before."));
					}
					else if(DateTime.parseRfc3339(updateTime).getValue() < DateTime.parseRfc3339(vizTime).getValue())
					{
						// never gonna happen
					}
					else{
						/*
						response.getWriter().println(
								GSON.toJson("There are updates at ("+ 
										updateTime
										+") since last time (" + vizTime + ") we visuzalized. Initiate Download Again."));
						*/
						diffedList.remove(request.getParameter("doc_id"));
						downloadedList.remove(request.getParameter("doc_id"));
						
						BufferedReader br = null;
						BufferedWriter bw = null;
						BufferedReader br1 = null;
						BufferedWriter bw1 = null;
						try{
						/**
						 * read the diffedListFile file, modify it and save it back
						 */
						br = new BufferedReader(new FileReader(diffedListFile));
						bw = new BufferedWriter(new FileWriter("diffedListFile.tmp"));
						
						String line = null;
						while ((line = br.readLine()) != null) {
							
							if(!line.startsWith(request.getParameter("doc_id"))){
								
								bw.write(line);
								bw.newLine();
							}
							else{

							}
						}
						/**
						 * read the downloadedList file, modify it and save it back
						 */
						br1 = new BufferedReader(new FileReader(downloadedListFile));
						bw1 = new BufferedWriter(new FileWriter("downloadedListFile.tmp"));
						
						line = null;
						while ((line = br1.readLine()) != null) {
							
							if(!line.startsWith(request.getParameter("doc_id"))){
								
								bw1.write(line);
								bw1.newLine();
							}
							else{

							}
						}
						
						}catch (Exception e){
							response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
							response.getWriter().print("Updateing DiffedList File Exception"); 
							return;
						} finally{
							try{
								if(br != null)
									br.close();
								if(br1 != null)
									br1.close();
							}catch (IOException e){
								response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
								response.getWriter().print("Updateing DiffedList File Exception");
								return;
							}
							try{
								if(bw != null)
									bw.close();
								if(bw1 != null)
									bw1.close();
							}catch (IOException e){
								response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
								response.getWriter().print("Updateing DiffedList File Exception");
								return;
							}
						}
						// once everything is complete, delete old files
						
						diffedListFile.delete();
						// And rename tmp file's name to old file name
						File newFile = new File("diffedListFile.tmp");
						newFile.renameTo(diffedListFile);
						
						downloadedListFile.delete();
						// And rename tmp file's name to old file name
						newFile = new File("downloadedListFile.tmp");
						newFile.renameTo(downloadedListFile);
						
						// Initiate a new list request and download thread running in background
						initiateListRevisionsRequest(request, response, tokenData);
					}

				} catch (IOException e) {
					response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
					response.getWriter().print(
							GSON.toJson("Failed to read data from Google. "
									+ e.getMessage()));
				}

				return;
			}
			else if (diffingList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
				response.getWriter().print(
						GSON.toJson("The Document "
								+ request.getParameter("doc_name")
								+ " has been downloaded before."));
				return;
			}
			//should never happen here
			else if (downloadedList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
				response.getWriter().print(
						GSON.toJson("The Document "
								+ request.getParameter("doc_name")
								+ " has been downloaded before."));
				return;
			}
			//should never happen here
			else if (downloadingList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
				response.getWriter()
						.print(GSON
								.toJson("The Document downloading is in progress now. Please wait."));
				return;
			}
			else{
				initiateListRevisionsRequest(request, response, tokenData);
				
				return;
			}
		}
		private void initiateListRevisionsRequest(HttpServletRequest request,
				HttpServletResponse response, String tokenData) throws IOException{
			try {
				// Build credential from stored token data.
				GoogleCredential credential = new GoogleCredential.Builder()
						.setJsonFactory(JSON_FACTORY)
						.setTransport(TRANSPORT)
						.setClientSecrets(CLIENT_ID, CLIENT_SECRET)
						.build()
						.setFromTokenResponse(
								JSON_FACTORY.fromString(tokenData,
										GoogleTokenResponse.class));
				// Create a new authorized API client.
				Drive service = new Drive.Builder(TRANSPORT, JSON_FACTORY,
						credential).setApplicationName(APPLICATION_NAME)
						.build();

				// Get a list of revisions .
				RevisionList revisions = service
						.revisions()
						.list(request.getParameter("doc_id"))
						.setFields(
								"items(exportLinks,id,lastModifyingUserName,modifiedDate)")
						.execute();

				response.setStatus(HttpServletResponse.SC_OK);
				response.getWriter().print(
						GSON.toJson("Downloading start. The document has #"
								+ revisions.getItems().size()
								+ " revisions. It may take up to " + 1
								* revisions.getItems().size() + " seconds."));

				// Initiate a new download thread running in background

				downloadRevisions(request.getParameter("doc_id"),
						request.getParameter("doc_name"), revisions, service);


			} catch (IOException e) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Failed to read data from Google. "
								+ e.getMessage()));
			}
		}
		
		/**
		 * Use a new Thread to download the revision documents TODO should be
		 * optimized by using gzip compress, header "Accept-Encoding: gzip"
		 * 
		 * @param docId
		 * @param revisions
		 * @param service
		 */
		private void downloadRevisions(final String docId,
				final String docName, final RevisionList revisions,
				final Drive service) {

			Thread thread = new Thread(new Runnable() {
				@Override
				public void run() {

					try {
						// downloading percent out of 100
						downloadingList.put(docId, 0);

						// TODO we may don't need a downloadingList to be saved
						// in file
						// FileWriter downloadFW = new
						// FileWriter(downloadingListFile,true);

						// Make a new sub-directory for each document and a
						// list.txt file to index revisions
						// TODO List file should include revisions file name,
						// revisions author name, and ??
						// any thing that we will need for the (whole) revision
						// in the future
						File fileDir = new File(revisionFileDir + docId);
						fileDir.mkdirs();
						File fileList = new File(revisionFileDir + docId + '/'
								+ "list.txt");
						BufferedWriter bw = new BufferedWriter(new FileWriter(
								fileList));

						// Counting revision numbers for counting progress or
						// debugging
						int i = 0;
						int total = revisions.getItems().size();

						for (Revision revision : revisions.getItems()) {

							System.out.println("Thread running: " + i);
							if (revision.getExportLinks() != null
									&& revision.getExportLinks().get(
											"text/plain") != null
									&& revision.getExportLinks()
											.get("text/plain").length() > 0) {

								// Using GZip way to download
								HttpRequest httpGet = service
										.getRequestFactory().buildGetRequest(
												new GenericUrl(revision
														.getExportLinks().get(
																"text/plain")));
								httpGet.getHeaders().setAcceptEncoding("gzip");
								// NO USE
								// httpGet.getHeaders().set("Accept-Charset",
								// "ISO-8859-1");

								HttpResponse resp = httpGet.execute();

								// File Name
								String revisionFileName = revision.getId()
										+ "_"
										+ PST.format(new Date(revision
												.getModifiedDate().getValue()));
								FileOutputStream outputstream = new FileOutputStream(
										new File(revisionFileDir + docId + '/'
												+ revisionFileName));
								IOUtils.copy(resp.getContent(), outputstream,
										true);
								outputstream.close();

								System.out.println("downloading: "
										+ revisionFileName);

								// for polling purpose
								downloadingList.put(docId, i * 100 / total);

								// assembly the list.txt index file
								bw.write(revisionFileName + "@"
										+ revision.getLastModifyingUserName());
								bw.newLine();
							}

							// Counting revision numbers for counting progress
							// or debugging
							i++;
						}

						//doc id & doc name in the file
						downloadedList.put(docId, docName);
						FileWriter doneFW = new FileWriter(downloadedListFile,
								true);
						doneFW.write(docId + ":" + docName
								+ System.getProperty("line.separator"));
						doneFW.close();

						downloadingList.remove(docId);

						bw.close();

						System.out.println("Downloading Done. Document Id: "
								+ docId);

					} catch (IOException e) {
						Log.info("WriteToFile Fail", e.toString());
						e.printStackTrace();
					} finally {
						// if( bw !=null)
						// bw.close();
					}
				}
			});
			thread.start();
		}
	}

	/**
	 * Check the revisions downloading/diff task with given doc_id.
	 */
	public static class PollingServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {

			if (request.getParameter("doc_id") == null
					|| request.getParameter("mode") == null) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Document Id not provided."));
				return;
			}

			// Wait 2.5 sec to see if the downloading has done. Save network
			// traffic
			try {
				Thread.sleep(2500);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			/*
			 * search for the downloadingList and downloadedList to see whether
			 * we need to initiate a new API call and downloading process
			 */
			// polling for download tasks
			if (request.getParameter("mode").equals("download")) {
				if (downloadedList.containsKey(request.getParameter("doc_id"))) {
					response.setStatus(HttpServletResponse.SC_ACCEPTED);
					response.getWriter().print(GSON.toJson(new Integer(100)));
					return;
				}

				if (downloadingList.containsKey(request.getParameter("doc_id"))) {
					response.setStatus(HttpServletResponse.SC_ACCEPTED);
					response.getWriter().print(
							GSON.toJson(downloadingList.get(request
									.getParameter("doc_id"))));
					return;
				}
			}
			// polling for diff tasks
			else if (request.getParameter("mode").equals("diff")) {
				if (diffedList.containsKey(request.getParameter("doc_id"))) {
					response.setStatus(HttpServletResponse.SC_ACCEPTED);
					response.getWriter().print(GSON.toJson(new Integer(100)));
					return;
				}

				if (diffingList.containsKey(request.getParameter("doc_id"))) {
					response.setStatus(HttpServletResponse.SC_ACCEPTED);
					response.getWriter().print(
							GSON.toJson(diffingList.get(request
									.getParameter("doc_id"))));
					return;
				}
			}
			// whatever, save for future polling tasks
			else {
				System.out.println("Polling Error Mode: "
						+ request.getParameter("mode"));
			}
		}

	}

	/**
	 * Analyzing the diff and generate the intermediate result
	 */
	public static class DiffRevisionsServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			// Only do diff for connected users.
			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
			if (request.getParameter("doc_id") == null) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Document Id not provided."));
				return;
			}

			/*
			 * search for the diffingList and diffedList to see whether we need
			 * to initiate a new diff process
			 */

			if (diffedList.containsKey(request.getParameter("doc_id"))) {
				
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
				response.getWriter()
						.print(GSON
								.toJson("The Document has been visualized before."));
				return;
			}

			if (!downloadedList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter()
						.print(GSON
								.toJson("Document hasn't been downloaded. Please download it first."));
				return;
			}

			if (diffingList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_ACCEPTED);
				response.getWriter()
						.print(GSON
								.toJson("The Document diff-ing is in progress now. Please wait."));
				return;
			}

			response.setStatus(HttpServletResponse.SC_OK);
			response.getWriter().print(GSON.toJson("Diff-ing task start."));
			
			// pass update time parameter, because Google Doc's lastModifiedDate doesn't equal to 
			// last Revision's lastModifiedDate
			try {
				// Build credential from stored token data.
				GoogleCredential credential = new GoogleCredential.Builder()
						.setJsonFactory(JSON_FACTORY)
						.setTransport(TRANSPORT)
						.setClientSecrets(CLIENT_ID, CLIENT_SECRET)
						.build()
						.setFromTokenResponse(
								JSON_FACTORY.fromString(tokenData,
										GoogleTokenResponse.class));
				// Create a new authorized API client.
				Drive service = new Drive.Builder(TRANSPORT, JSON_FACTORY,
						credential).setApplicationName(APPLICATION_NAME)
						.build();

				// Get a list of revisions .
				com.google.api.services.drive.model.File file = service.files().get(request.getParameter("doc_id")).setFields("modifiedDate")
						.execute();
				String updateTime = PST.format(new Date(file.getModifiedDate().getValue()));
				// subtract the milsecond in order to simplify the comparison 	

				// Initiate a new diff thread running in background, because it will
				// take long time to run
				diffRevisions(request.getParameter("doc_id"),
						request.getParameter("doc_name"), updateTime);
				
			} catch (IOException e) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Failed to read data from Google. "
								+ e.getMessage()));
			}

			return;

		}

		private void diffRevisions(final String docId, final String docName, final String updateTime) {

			Thread thread = new Thread(new Runnable() {
				@Override
				public void run() {

					try {
						// diff-ing percent out of 100
						diffingList.put(docId, 0);
						// For Debug showing calculation time
						long start_time = System.currentTimeMillis();

						File listFileDir = new File(revisionFileDir + docId);

						if (listFileDir.exists()) {
							Scanner revisionListScanner = new Scanner(new File(
									listFileDir + "/list.txt"));
							LinkedHashMap<String, String> revisionsNameAuthorPairList = new LinkedHashMap<String, String>();
							while (revisionListScanner.hasNextLine()) {
								// Key/Value pair, revision's file name and
								// revision's lastUpdated author name

								String[] revisionListPair = revisionListScanner
										.nextLine().split("@");
								revisionsNameAuthorPairList.put(
										revisionListPair[0],
										revisionListPair[1]);
							}

							revisionListScanner.close();

							// Create a new JSON file in the directory for
							// rendering visualization
							File intermediateData = new File(listFileDir
									+ "/historyflow.json");
							BufferedWriter bw = new BufferedWriter(
									new FileWriter(intermediateData));

							// Add authors to the JSON file first
							ArrayList<String> authorList = new ArrayList<String>();
							Iterator<String> authorIterator = revisionsNameAuthorPairList
									.values().iterator();
							while (authorIterator.hasNext()) {
								String author = authorIterator.next();
								if (authorList.contains(author)) {
									// Author already exists in the authorList
								} else {
									authorList.add(author);
								}
							}

							bw.write("{");
							bw.newLine();
							bw.write(GSON.toJson("docId") + ":"
									+ GSON.toJson(docId));
							bw.newLine();
							bw.write("," + GSON.toJson("docName") + ":"
									+ GSON.toJson(docName));
							bw.newLine();
							bw.write("," + GSON.toJson("authors") + ":"
									+ GSON.toJson(authorList));
							bw.newLine();

							// It should never happen that the revisionsList has
							// ZERO items

							Iterator<String> iteratorFileName = revisionsNameAuthorPairList
									.keySet().iterator();
							String newRevisionName;

							MyRevision oldRevision = null;
							MyRevision newRevision = null;
							ArrayList<MySegment> segments = new ArrayList<MySegment>();

							// assembly the historyflow.json file
							bw.write("," + GSON.toJson("revisions") + ":[");
							bw.newLine();

							// for polling purpose
							int i = 0;
							int total = revisionsNameAuthorPairList.size();

							// If there are less than two revisions, still need
							// to be diff and generate a oldRevision with
							// segments
							while (iteratorFileName.hasNext()) {
								newRevisionName = iteratorFileName.next();
								// Create a new MyRevision object from the
								// revision file
								newRevision = new MyRevision();
								newRevision.setDocId(docId);
								newRevision.setAuthorId(authorList
										.indexOf(revisionsNameAuthorPairList
												.get(newRevisionName)));
								String[] revisionIdTimePair = newRevisionName
										.split("_");
								newRevision
										.setRevisionId(revisionIdTimePair[0]);
								newRevision.setTime(revisionIdTimePair[1]);

								// Read revision file content from the file
								BufferedReader br = new BufferedReader(
										new FileReader(listFileDir + "/"
												+ newRevisionName));
								StringBuffer str = new StringBuffer();
								String line = br.readLine();
								while (line != null) {
									str.append(line);
									str.append("\n");
									line = br.readLine();
								}

								newRevision.setContent(str.toString());
								newRevision.setRevisionLength(newRevision.getContent().length());
								br.close();

								/** Diff two adjacent revisions
								 *  The Core Algorithm
								 */
								diff(oldRevision, newRevision, segments);
								if (oldRevision != null){
									bw.write(",");
									bw.newLine();
								}
								bw.write(GSON.toJson(newRevision));
								bw.newLine();

								// update all the segments index in this "newer"
								// revision
								// to prepare for next calculation
								newRevision.updateSegmentsIndex();
								
								oldRevision = newRevision;

								// for polling purpose
								i++;
								// TODO error, while calculating, many
								// revisions? many items?
								diffingList.put(docId, i * 100 / total);

							}
							bw.write("]");
							bw.newLine();
							bw.write("," + GSON.toJson("segments") + ":"
									+ GSON.toJson(segments));
							bw.newLine();
							bw.write("}");
							bw.close();

							// create a new segments list file to store all
							// segments' content for the content retrieving function
							File segmentsContent = new File(listFileDir
									+ "/segmentsContent.txt");
							BufferedWriter segmentsBw = new BufferedWriter(
									new FileWriter(segmentsContent));
							for (MySegment s : segments) {
								segmentsBw.write(GSON.toJson(s.getContent()));
								segmentsBw.newLine();
							}
							segmentsBw.close();

							//update the diff-ed list adding the update time
							diffedList.put(docId, updateTime);
							
							FileWriter doneFW = new FileWriter(diffedListFile,
									true);
							doneFW.write(docId + ":" + updateTime
									+ System.getProperty("line.separator"));
							doneFW.close();

							diffingList.remove(docId);

							bw.close();

							System.out.println("Diff Task Done. Document Id: "
									+ docId);
						}

						// Should never happen, The document was downloaded but
						// the list.txt file was broken
						else {

						}

						// For Debug showing calculation time
						long end_time = System.currentTimeMillis();
						System.out
								.printf("Elapsed time: %f in diff-ing revisions to generate historyflow.json file\n",
										((end_time - start_time) / 1000.0));

					} catch (IOException e) {
						Log.info("WriteToFile Fail", e.toString());
						e.printStackTrace();
					} finally {
						// if( bw !=null)
						// bw.close();
					}
				}

				// TODO move the diff(old,new,segmentList) function here?
			});
			thread.start();
		}

		/**
		 * The function to calculate the difference between two adjacent
		 * revisions using google-diff-match-patch library's diff results as input.
		 * The three parameters are:
		 * 
		 * @param oldRevision
		 *            MyRevision represents the older revision object
		 * @param newRevision
		 *            MyRevision represents the newer revision object
		 * @param segmentList
		 *            ArrayList<MySegment> represents the whole segments list
		 *            for one document The result will be stored in each
		 *            revisions segmentsList and the document's whole segments
		 *            list
		 * @author Dakuo Wang updated July 23, 2014
		 */
		private void diff(MyRevision oldRevision, MyRevision newRevision,
				ArrayList<MySegment> segmentList) {
			int segmentIndex = segmentList.size();
			if (oldRevision == null) {
				MySegment insertSegment = new MySegment();
				insertSegment.setSegmentId(segmentIndex++);
				insertSegment.setAuthorId(newRevision.getAuthorId());
				insertSegment.setContent(newRevision.getContent());
				insertSegment.setStartIndex(0);
				insertSegment.setLength(newRevision.getContent().length());
				if (insertSegment.getLength() == 0)
					insertSegment.setEndIndex(0);
				else
					insertSegment.setEndIndex(insertSegment.getLength() - 1);
				insertSegment.setVisible(true);

				newRevision.addSegment(insertSegment);
				segmentList.add(insertSegment);
			} else {

				/**
				 * To diff the text in char level
				 * 
				 * 
				 * LinkedList<Diff> diffs = DMP.diff_main(
				 * oldRevision.getContent(), newRevision.getContent(), false);
				 * DMP.diff_cleanupEfficiency(diffs);
				 */

				/**
				 * To diff the text in word level, using the customized version
				 * diff
				 */
				LinesToCharsResult lines = DMP.diff_linesToWords(
						oldRevision.getContent(), newRevision.getContent());
				LinkedList<Diff> diffs = DMP.diff_main(lines.chars1,
						lines.chars2);
				DMP.diff_charsToLines(diffs, lines.lineArray);

				int charPointer1 = 0;
				int charPointer2 = 0;
				int segmentsSize = oldRevision.getSegments().size();
				
				/**
				 * Try to handle the movement detection 
				 * Firstly Delete then Add 
				 * 
				 * The idea is whenever a DELETE occurs, we save the DELETE DIFF CONTENT(String) into a deleteSegmentMap,
				 * the KEY for the content in the map is the charpointer1 in the older revision. If there is a ADD occurs afterward,
				 * we compare the ADD CONTENT(String) with deleteSegmentMap's element CONTENT(String). If there is a match, we will 
				 * then searching for all segments existing in the content in the old revision, and make a copy for each of 
				 * them(SEGMENTS) in the new revision, instead of Creating A New SEGMENT.
				 * 
				 **/
				//detect only segment's length more than 20 characters
				int moveDetectThreshhold = 20;

				HashMap<Integer, String> deleteSegmentMap = new HashMap<Integer,String>();
				/**
				 * Firstly Add then Delete 
				 * The idea is whenever a ADD occurs, we save the ADD DIFF CONTENT(String) into a addSegmentMap,
				 * the KEY for the segment in the map is the SegmentID in the newer revision. If there is a DELETE occurs afterward,
				 * we compare the DELETE CONTENT(String) with deleteSegmentMap's element CONTENT(String). If there is a match, we will 
				 * then searching for all segments existing in the DIFF CONTENT in the old revision, and then assign the first found 
				 * segment id as the fatherSegmentId for the ADD segment in the new revision.
				 */
				HashMap<Integer, String> addSegmentMap = new HashMap<Integer,String>();
				/**
				 * The END of handling movement detection
				 */

				for (Diff diff : diffs) {
					Operation diffType = diff.operation;
					String diffContent = diff.text;
					int diffLength = diffContent.length();
					
					if (diff.operation.equals(diff_match_patch.Operation.DELETE)) {
						
						/**
						 * Try to handle the movement detection 
						 **/
						if(diffLength>=moveDetectThreshhold){
							/**
							 * Firstly ADD then DELETE
							 **/
							Iterator<Entry<Integer, String>> iterator = addSegmentMap.entrySet().iterator();
							boolean moveFlag = false;
							
							while (iterator.hasNext()) {
							    Map.Entry<Integer,String> pairs = (Map.Entry<Integer,String>)iterator.next();
							    String value =  pairs.getValue();
							    Integer key = pairs.getKey();
							    // To delete those annoying whitespace in the beginning and at the end, and in the middle :)
							    if(value.replaceAll("\\s+","").equals(diffContent.replaceAll("\\s+",""))){
								//if(value.equals(diffContent)){
									moveFlag = true;
									/** 
									 * A superb algorithm(VARIANT) to look for existing segments in a given content string in the old revision 
									 * Traverse old revision's segments to divide segment to new segment
									 */
									
									for (int i = 0; i < segmentsSize; i++) {
										MySegment segment = oldRevision.getSegments()
												.get(i);

										if (charPointer1 > segment.getEndIndex())
											continue;
										else if ((charPointer1 + diffLength - 1) < segment
												.getStartIndex())
											break;
										// The segment is at the same size as the diff content
										else if (charPointer1 == segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) == segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											break;
										} 
										// 
										else if (charPointer1 == segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) > segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											break;
										} 
										// 
										else if (charPointer1 == segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) < segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											break;
										}
										//
										else if (charPointer1 > segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) <= segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											segmentList.get(key).setOffsetInFatherSegment(charPointer1-segment.getStartIndex());
											segmentList.get(key).setAuthorId(segment.getAuthorId());
											break;
										} 
										//
										else if (charPointer1 > segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) > segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											segmentList.get(key).setOffsetInFatherSegment(charPointer1-segment.getStartIndex());
											segmentList.get(key).setAuthorId(segment.getAuthorId());
											break;
										} 
										//the following occasions should never occur
										else if (charPointer1 < segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) == segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											break;
										} 
										//
										else if (charPointer1 < segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) > segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											break;
										} 
										//
										else if (charPointer1 < segment.getStartIndex()
												&& (charPointer1 + diffLength - 1) < segment
														.getEndIndex()) {
											segmentList.get(key).setFatherSegmentIndex(segment.getSegmentId());
											break;
										}
									}
									
									/** End of finding the segments ID in the diff content in the old revision**/
									break;
								}
							}
							
							/**
							 * The END of handling ADD-DELETE movement detection
							 */
							
							/**
							 * Firstly Delete then Add
							 */
							if(moveFlag==false){
								deleteSegmentMap.put(charPointer1,diffContent);
							}
						}
						
						/**
						 * The END of handling movement detection
						 */
						
						charPointer1 += diffLength;
					}
					else if (diffType.equals(diff_match_patch.Operation.INSERT)) {
						/**
						 * Try to handle the movement detection 
						 * Firstly Delete then Add or Firstly Add then Delete 
						 **/
						if(diffLength>=moveDetectThreshhold){
							Iterator<Entry<Integer, String>> iterator = deleteSegmentMap.entrySet().iterator();
							boolean moveFlag = false;
							
							while (iterator.hasNext()) {
							    Map.Entry<Integer,String> pairs = (Map.Entry<Integer,String>)iterator.next();
							    String value =  pairs.getValue();
							    Integer key = pairs.getKey();
								//if(value.equals(diffContent)){
							    if(value.replaceAll("\\s+","").equals(diffContent.replaceAll("\\s+",""))){
									moveFlag = true;
									/**
									 * Find the segments in the diff content in the old revision
									 */
									int charPointer = key;
									/** 
									 * A superb algorithm to look for existing segments in a given content string in the old revision 
									 * Traverse old revision's segments to divide segment to new segment
									 */
									
									for (int i = 0; i < segmentsSize; i++) {
										MySegment segment = oldRevision.getSegments()
												.get(i);

										if (charPointer > segment.getEndIndex())
											continue;
										else if ((charPointer + diffLength - 1) < segment
												.getStartIndex())
											break;
										// The segment is at the same size as the diff content
										else if (charPointer == segment.getStartIndex()
												&& (charPointer + diffLength - 1) == segment
														.getEndIndex()) {
											segment.setNewStartIndex(charPointer2);
											segment.setNewEndIndex(segment
													.getNewStartIndex()
													+ segment.getLength() - 1);
											newRevision.addSegment(segment);
											charPointer2 += segment.getLength();
										} 
										// 
										else if (charPointer == segment.getStartIndex()
												&& (charPointer + diffLength - 1) > segment
														.getEndIndex()) {
											segment.setNewStartIndex(charPointer2);
											segment.setNewEndIndex(segment
													.getNewStartIndex()
													+ segment.getLength() - 1);
											newRevision.addSegment(segment);
											charPointer2 += segment.getLength();
										} 
										// 
										else if (charPointer == segment.getStartIndex()
												&& (charPointer + diffLength - 1) < segment
														.getEndIndex()) {
											MySegment targetSegment = new MySegment();
											targetSegment
													.setAuthorId(segment.getAuthorId());
											targetSegment.setLength(diffLength
													- segment.getStartIndex()
													+ charPointer);
											targetSegment.setStartIndex(charPointer2);
											targetSegment.setEndIndex(targetSegment
													.getStartIndex()
													+ targetSegment.getLength() - 1);
											targetSegment.setContent(diffContent.substring(
													segment.getStartIndex() - charPointer,
													segment.getStartIndex() - charPointer
															+ targetSegment.getLength()));
											targetSegment.setSegmentId(segmentIndex++);
											targetSegment.setFatherSegmentIndex(segment
													.getSegmentId());
											targetSegment.setOffsetInFatherSegment(0);
											targetSegment.setVisible(true);

											newRevision.addSegment(targetSegment);
											segmentList.add(targetSegment);

											charPointer2 += targetSegment.getLength();
										}
										//
										else if (charPointer > segment.getStartIndex()
												&& (charPointer + diffLength - 1) <= segment
														.getEndIndex()) {

											MySegment targetSegment = new MySegment();
											targetSegment
													.setAuthorId(segment.getAuthorId());
											targetSegment.setLength(diffLength);
											targetSegment.setStartIndex(charPointer2);
											targetSegment.setEndIndex(targetSegment
													.getStartIndex()
													+ targetSegment.getLength() - 1);
											targetSegment.setContent(diffContent);
											targetSegment.setSegmentId(segmentIndex++);
											// targetSegment.setTime(newRevision.getTime());
											targetSegment.setFatherSegmentIndex(segment
													.getSegmentId());
											targetSegment
													.setOffsetInFatherSegment(charPointer
															- segment.getStartIndex());
											targetSegment.setVisible(true);

											newRevision.addSegment(targetSegment);
											segmentList.add(targetSegment);
											charPointer2 += targetSegment.getLength();
										} else if (charPointer > segment.getStartIndex()
												&& (charPointer + diffLength - 1) > segment
														.getEndIndex()) {

											MySegment targetSegment = new MySegment();
											targetSegment.setSegmentId(segmentIndex++);
											targetSegment
													.setAuthorId(segment.getAuthorId());
											// targetSegment.setTime(newRevision.getTime());
											targetSegment.setFatherSegmentIndex(segment
													.getSegmentId());
											targetSegment
													.setOffsetInFatherSegment(charPointer
															- segment.getStartIndex());
											targetSegment.setStartIndex(charPointer2);
											targetSegment.setLength(segment.getEndIndex()
													- charPointer + 1);
											targetSegment.setEndIndex(charPointer2
													+ targetSegment.getLength() - 1);
											targetSegment.setContent(diffContent.substring(
													0, segment.getEndIndex() - charPointer
															+ 1));
											targetSegment.setVisible(true);

											newRevision.addSegment(targetSegment);
											segmentList.add(targetSegment);
											charPointer2 += targetSegment.getLength();
										} else if (charPointer < segment.getStartIndex()
												&& (charPointer + diffLength - 1) == segment
														.getEndIndex()) {
											segment.setNewStartIndex(charPointer2);
											segment.setNewEndIndex(segment
													.getNewStartIndex()
													+ segment.getLength() - 1);
											newRevision.addSegment(segment);
											charPointer2 += segment.getLength();
										} else if (charPointer < segment.getStartIndex()
												&& (charPointer + diffLength - 1) > segment
														.getEndIndex()) {

											segment.setNewStartIndex(charPointer2);
											segment.setNewEndIndex(segment
													.getNewStartIndex()
													+ segment.getLength() - 1);

											newRevision.addSegment(segment);
											charPointer2 += segment.getLength();
										} else if (charPointer < segment.getStartIndex()
												&& (charPointer + diffLength - 1) < segment
														.getEndIndex()) {

											MySegment targetSegment = new MySegment();
											targetSegment
													.setAuthorId(segment.getAuthorId());
											targetSegment.setLength(charPointer
													+ diffLength - segment.getStartIndex());
											targetSegment.setStartIndex(charPointer2);
											targetSegment.setEndIndex(targetSegment
													.getStartIndex()
													+ targetSegment.getLength() - 1);
											targetSegment.setContent(diffContent.substring(
													segment.getStartIndex() - charPointer,
													segment.getStartIndex() - charPointer
															+ targetSegment.getLength()));
											targetSegment.setSegmentId(segmentIndex++);
											// targetSegment.setTime(newRevision.getTime());
											targetSegment.setFatherSegmentIndex(segment
													.getSegmentId());
											targetSegment.setOffsetInFatherSegment(0);
											targetSegment.setVisible(true);

											newRevision.addSegment(targetSegment);
											segmentList.add(targetSegment);
											charPointer2 += targetSegment.getLength();
										}

									}
									
									/** End of finding the segments ID in the diff content in the old revision**/
									
									break;
								}
							    
							}
							/**
							 * In this case, we couldn't find the movement segment. In other words, this is not a DELETE-ADD move.
							 * But it could be either a NEW Segment or a ADD-DELETE move.
							 */
							if(moveFlag==false){
								MySegment insertSegment = new MySegment();
								insertSegment.setSegmentId(segmentIndex++);
								insertSegment.setAuthorId(newRevision.getAuthorId());
								// insertSegment.setTime(newRevision.getTime());
								insertSegment.setContent(diffContent);
								insertSegment.setStartIndex(charPointer2);
								insertSegment.setLength(diffLength);
								if (charPointer2 == 0 && diffLength == 0)
									insertSegment.setEndIndex(0);
								else
									insertSegment.setEndIndex(charPointer2 + diffLength
											- 1);
								insertSegment.setVisible(true);
								newRevision.addSegment(insertSegment);
								segmentList.add(insertSegment);
								charPointer2 += diffLength;
								
								/**
								 * Try to handle the movement detection 
								 * Firstly ADD then DELETE
								 **/
								
								addSegmentMap.put(insertSegment.getSegmentId(),insertSegment.getContent());
								
								/**
								 * The END of handling ADD-DELETE movement detection
								 */
							}

						}
						
						/**
						 * The END of handling movement detection,
						 */
						
						else{
							/**
							 * In this case, the content is not more than the movement detection threshold
							 */
							MySegment insertSegment = new MySegment();
							insertSegment.setSegmentId(segmentIndex++);
							insertSegment.setAuthorId(newRevision.getAuthorId());
							// insertSegment.setTime(newRevision.getTime());
							insertSegment.setContent(diffContent);
							insertSegment.setStartIndex(charPointer2);
							insertSegment.setLength(diffLength);
							if (charPointer2 == 0 && diffLength == 0)
								insertSegment.setEndIndex(0);
							else
								insertSegment.setEndIndex(charPointer2 + diffLength
										- 1);
							insertSegment.setVisible(true);
							newRevision.addSegment(insertSegment);
							segmentList.add(insertSegment);
							charPointer2 += diffLength;
						}
					}  else {
						/** 
						 * A superb algorithm to look for existing segments in a given content string in the old revision 
						 * Traverse old revision's segments to divide segment to new segment
						 */

						for (int i = 0; i < segmentsSize; i++) {
							MySegment segment = oldRevision.getSegments()
									.get(i);

							if (charPointer1 > segment.getEndIndex())
								continue;
							else if ((charPointer1 + diffLength - 1) < segment
									.getStartIndex())
								break;
							// The segment is at the same size as the diff content
							else if (charPointer1 == segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) == segment
											.getEndIndex()) {
								segment.setNewStartIndex(charPointer2);
								segment.setNewEndIndex(segment
										.getNewStartIndex()
										+ segment.getLength() - 1);
								newRevision.addSegment(segment);
								charPointer2 += segment.getLength();
							} 
							// 
							else if (charPointer1 == segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) > segment
											.getEndIndex()) {
								segment.setNewStartIndex(charPointer2);
								segment.setNewEndIndex(segment
										.getNewStartIndex()
										+ segment.getLength() - 1);
								newRevision.addSegment(segment);
								charPointer2 += segment.getLength();
							} 
							// 
							else if (charPointer1 == segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) < segment
											.getEndIndex()) {
								MySegment targetSegment = new MySegment();
								targetSegment
										.setAuthorId(segment.getAuthorId());
								targetSegment.setLength(diffLength
										- segment.getStartIndex()
										+ charPointer1);
								targetSegment.setStartIndex(charPointer2);
								targetSegment.setEndIndex(targetSegment
										.getStartIndex()
										+ targetSegment.getLength() - 1);
								targetSegment.setContent(diffContent.substring(
										segment.getStartIndex() - charPointer1,
										segment.getStartIndex() - charPointer1
												+ targetSegment.getLength()));
								targetSegment.setSegmentId(segmentIndex++);
								targetSegment.setFatherSegmentIndex(segment
										.getSegmentId());
								targetSegment.setOffsetInFatherSegment(0);
								targetSegment.setVisible(true);

								newRevision.addSegment(targetSegment);
								segmentList.add(targetSegment);

								charPointer2 += targetSegment.getLength();
							}
							//
							else if (charPointer1 > segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) <= segment
											.getEndIndex()) {

								MySegment targetSegment = new MySegment();
								targetSegment
										.setAuthorId(segment.getAuthorId());
								targetSegment.setLength(diffLength);
								targetSegment.setStartIndex(charPointer2);
								targetSegment.setEndIndex(targetSegment
										.getStartIndex()
										+ targetSegment.getLength() - 1);
								targetSegment.setContent(diffContent);
								targetSegment.setSegmentId(segmentIndex++);
								// targetSegment.setTime(newRevision.getTime());
								targetSegment.setFatherSegmentIndex(segment
										.getSegmentId());
								targetSegment
										.setOffsetInFatherSegment(charPointer1
												- segment.getStartIndex());
								targetSegment.setVisible(true);

								newRevision.addSegment(targetSegment);
								segmentList.add(targetSegment);
								charPointer2 += targetSegment.getLength();
							} else if (charPointer1 > segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) > segment
											.getEndIndex()) {

								MySegment targetSegment = new MySegment();
								targetSegment.setSegmentId(segmentIndex++);
								targetSegment
										.setAuthorId(segment.getAuthorId());
								// targetSegment.setTime(newRevision.getTime());
								targetSegment.setFatherSegmentIndex(segment
										.getSegmentId());
								targetSegment
										.setOffsetInFatherSegment(charPointer1
												- segment.getStartIndex());
								targetSegment.setStartIndex(charPointer2);
								targetSegment.setLength(segment.getEndIndex()
										- charPointer1 + 1);
								targetSegment.setEndIndex(charPointer2
										+ targetSegment.getLength() - 1);
								targetSegment.setContent(diffContent.substring(
										0, segment.getEndIndex() - charPointer1
												+ 1));
								targetSegment.setVisible(true);

								newRevision.addSegment(targetSegment);
								segmentList.add(targetSegment);
								charPointer2 += targetSegment.getLength();
							} else if (charPointer1 < segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) == segment
											.getEndIndex()) {
								segment.setNewStartIndex(charPointer2);
								segment.setNewEndIndex(segment
										.getNewStartIndex()
										+ segment.getLength() - 1);
								newRevision.addSegment(segment);
								charPointer2 += segment.getLength();
							} else if (charPointer1 < segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) > segment
											.getEndIndex()) {

								segment.setNewStartIndex(charPointer2);
								segment.setNewEndIndex(segment
										.getNewStartIndex()
										+ segment.getLength() - 1);

								newRevision.addSegment(segment);
								charPointer2 += segment.getLength();
							} else if (charPointer1 < segment.getStartIndex()
									&& (charPointer1 + diffLength - 1) < segment
											.getEndIndex()) {

								MySegment targetSegment = new MySegment();
								targetSegment
										.setAuthorId(segment.getAuthorId());
								targetSegment.setLength(charPointer1
										+ diffLength - segment.getStartIndex());
								targetSegment.setStartIndex(charPointer2);
								targetSegment.setEndIndex(targetSegment
										.getStartIndex()
										+ targetSegment.getLength() - 1);
								targetSegment.setContent(diffContent.substring(
										segment.getStartIndex() - charPointer1,
										segment.getStartIndex() - charPointer1
												+ targetSegment.getLength()));
								targetSegment.setSegmentId(segmentIndex++);
								// targetSegment.setTime(newRevision.getTime());
								targetSegment.setFatherSegmentIndex(segment
										.getSegmentId());
								targetSegment.setOffsetInFatherSegment(0);
								targetSegment.setVisible(true);

								newRevision.addSegment(targetSegment);
								segmentList.add(targetSegment);
								charPointer2 += targetSegment.getLength();
							}

						}
						/**
						 * THE END of the superb old revision traverse function 
						 */
						charPointer1 += diffLength;

					}
				}

			}
		}

	}

	/**
	 * TODO In the future, may should consider filtering the result and return
	 * partially data back Visualizing the intermediate result and return to
	 * javascript for rendering
	 */
	public static class VisualizeServlet extends HttpServlet {
		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
			if (request.getParameter("doc_id") == null) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Document Id not provided."));
				return;
			}

			/*
			 * search for the diffingList and diffedList to see whether we need
			 * to initiate a new diff process
			 */
			if (!downloadedList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter()
						.print(GSON
								.toJson("Document hasn't been downloaded. Please download it first."));
				return;
			}

			if (!diffedList.containsKey(request.getParameter("doc_id"))) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter()
						.print(GSON
								.toJson("The Document has not been visualized before. Pleae viz it first."));
				return;
			}

			/**
			 * TODO do we need a viz-ing status?
			 * 
			 * if (diffingList.containsKey(request.getParameter("doc_id"))) {
			 * response.setStatus(HttpServletResponse.SC_ACCEPTED);
			 * response.getWriter() .print(GSON .toJson(
			 * "The Document diff-ing is in progress now. Please wait."));
			 * return; }
			 */

			// TODO for now, the servlet just locates the JSON file and return
			// it to Javascript
			// no redenring or calculating at all

			File jsonFileDir = new File(revisionFileDir
					+ request.getParameter("doc_id"));
			if (!jsonFileDir.exists()) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Couldn't find the JSON file directory."));
				return;
			}
			/**
			 * Efficient way to do a file read, maybe should be adopted at all
			 * file read points
			 */
			
			BufferedReader br = new BufferedReader(new FileReader(jsonFileDir
					+ "/historyflow.json"));
			StringBuffer json = new StringBuffer();

			String line = br.readLine();
			int startIndex = 0;
			int endIndex = 99999; //ALERT! let's hope no document revision will exceed this number.
			// the first time visualization, there won't be start_rev_index and end_rev_index
			if (request.getParameter("start_rev_index") != null) {
				startIndex =  Integer.parseInt(request.getParameter("start_rev_index"));
			}
			if (request.getParameter("end_rev_index") != null) {
				endIndex =  Integer.parseInt(request.getParameter("end_rev_index")); 
			}
			
			int i = 0;
			boolean revisionZoneFlag = false;
			while (line != null) {
				// read the head 5 lines
				if(!revisionZoneFlag){
					json.append(line);
					i++; // use as line index
					if(i >= 5){
						revisionZoneFlag = true;
						i = 0; // use as revision index
					}
				}
				else{
					if(! line.startsWith(",")){

						i ++;
						if(i > startIndex && i<= endIndex+1){
							json.append(line);
						}
						else{
							if( line.startsWith("]")){
								revisionZoneFlag=false;
								i = 0; // use back as line index
								json.append(line);	
							}
						}
					}

					else{
						if(i > startIndex && i< endIndex+1){
							json.append(line);
						}
					}
				}
				line = br.readLine();
			}
			
			br.close();

			response.setStatus(HttpServletResponse.SC_OK);
			response.getWriter().print(GSON.toJson(json));
			
			return;

		}
	}

	/**
	 * TODO In the future, may should consider filtering the result and return
	 * partially data back 
	 * 
	 * Handling the information retrieve request for segment content
	 */
	public static class SegmentServlet extends HttpServlet {
		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
			if (request.getParameter("doc_id") == null
					|| request.getParameter("segment_id") == null) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Document / Segment Id not provided."));
				return;
			}

			// TODO for now, each segment content retrieving request initiate a
			// new File opening
			// Supper inefficient
			File listFileDir = new File(revisionFileDir
					+ request.getParameter("doc_id"));
			if (!listFileDir.exists()) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Couldn't find the JSON file directory."));
				return;
			}
			/**
			 * Efficient way to do a file read, maybe should be adopted at all
			 * file read points
			 */
			BufferedReader br = new BufferedReader(new FileReader(listFileDir
					+ "/segmentsContent.txt"));

			int counter = 0;
			int seg_id = Integer.parseInt(request.getParameter("segment_id"));
			String line = null;
			while ((line = br.readLine()) != null) {

				if (counter == seg_id) {
					break;
				}
				counter++;
			}
			br.close();

			response.setStatus(HttpServletResponse.SC_OK);
			response.getWriter().print(line);

			return;

		}
	}
	
	/**
	 * 
	 * The Servlet to handle user's request for changing a segment's author.
	 * All its children segments' author also need to be changed.
	 * So is the Revisions' author array
	 * @author dakuowang
	 *
	 */
	public static class ChangeSegmentAuthorServlet extends HttpServlet{

		private static final long serialVersionUID = 1L;
		
		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			response.setContentType("application/json");

			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
			if (request.getParameter("doc_id") == null
					|| request.getParameter("segment_id") == null 
					|| request.getParameter("author_id") == null 
					|| request.getParameter("rev_id") == null) {
				response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
				response.getWriter().print(
						GSON.toJson("Document / Segment / Author Id is not provided."));
				return;
			}

			File listFileDir = new File(revisionFileDir
					+ request.getParameter("doc_id"));
			if (!listFileDir.exists()) {
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print(
						GSON.toJson("Couldn't find the JSON file directory."));
				return;
			}
			
			BufferedReader br = null;
			BufferedWriter bw = null;
			try{
			/**
			 * read the historyflow.json file, modify it and save it back
			 */
			br = new BufferedReader(new FileReader(listFileDir
					+ "/historyflow.json"));
			bw = new BufferedWriter(new FileWriter(listFileDir + "/temp.json"));

			int seg_id = Integer.parseInt(request.getParameter("segment_id"));
			int rev_id =  Integer.parseInt(request.getParameter("rev_id")), rev_index=0;
			int author_id = Integer.parseInt(request.getParameter("author_id"));
			
			String line = null;
			Pattern p = Pattern.compile("(\\{\\\"segmentLength\\\":\\d+,\\\"authorId\\\":)(\\d+)(,\\\"fatherSegmentIndex\\\":)(-?\\d+)(,\\\"offsetInFatherSegment\\\":\\d+},?)");
			Matcher m = null;
			
			while ((line = br.readLine()) != null) {
				if(line.startsWith("{\"authorId\"")){
					if(rev_id == rev_index){
						Pattern p2 = Pattern.compile("(\\{\\\"authorId\\\":)(\\[?((\\d),?)+\\]?)(,.*)");
						Matcher m2 = p2.matcher(line);
						while(m2.find()){
							// means the revision author id is already an array
							if(m2.group(2).startsWith("[")){
								String[] items = m2.group(2).replaceAll("\\[", "").replaceAll("\\]", "").split(",");
								//int[] results = new int[items.length];
								int i =0;
								for ( i = 0; i < items.length; i++) {
								    /*try {
								        results[i] = Integer.parseInt(items[i]);
								    } catch (NumberFormatException nfe) {};
								    */
									// means the author id already in array
									if(Integer.parseInt(items[i]) == author_id){
										bw.write(line);
										break;
									}
								}
								//means the author id not in author array
								if(i==items.length){
									String s = m2.group(2).substring(0, m2.group(2).length() - 1);
									bw.write(m2.group(1)+s+","+author_id+"]"+m2.group(5));
								}
							}
							// means the author id is a single id
							else{
								if(author_id != Integer.parseInt(m2.group(2)))
									bw.write(m2.group(1) +"["+ m2.group(2)+","+author_id +"]" +m2.group(5));
								else
									bw.write(line);
							}
							bw.newLine();
						}
					}
					else{
						bw.write(line);
						bw.newLine();
					}
					rev_index++;
					
				}
				else if(line.startsWith(",\"segments\"")){
					HashSet<Integer> segIdSet = new HashSet<Integer>();
					segIdSet.add(seg_id);
					
					m = p.matcher(line);
					int counter = 0;
					
					bw.write(",\"segments\":[");
					
					while (m.find()) {
						// find the target segment to change author
						int fatherSegId = Integer.parseInt(m.group(4));
						
						if(segIdSet.contains(counter)){
							bw.write(m.group(1) + author_id +m.group(3)+m.group(4)+m.group(5));
						}
						else if(segIdSet.contains(fatherSegId)){
							bw.write(m.group(1) + author_id +m.group(3)+m.group(4)+m.group(5));
							segIdSet.add(counter);
						}
						// segments that are not targets
						else{
							bw.write(m.group(1) + m.group(2) +m.group(3)+m.group(4)+m.group(5));
						}
						counter++;
					}
					bw.write("]");
					bw.newLine();
				}
				else{
					bw.write(line);
					bw.newLine();
				}
			}
			
			}catch (Exception e){
				response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
				response.getWriter().print("Changing segment author_id Exception"); 
				return;
			} finally{
				try{
					if(br != null)
						br.close();
				}catch (IOException e){
					response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
					response.getWriter().print("Changing segment author_id Exception");
					return;
				}
				try{
					if(bw != null)
						bw.close();
				}catch (IOException e){
					response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
					response.getWriter().print("Changing segment author_id Exception");
					return;
				}
			}
			// once everything is complete, delete old files
			File oldFile = new File(listFileDir + "/historyflow.json");
			oldFile.delete();
			// And rename tmp file's name to old file name
			File newFile = new File(listFileDir + "/temp.json");
			newFile.renameTo(oldFile);
	
			response.setStatus(HttpServletResponse.SC_OK);
			response.getWriter().print("Segment "+ request.getParameter("segment_id") 
					+ " author change to "+request.getParameter("author_id"));

			return;

		}
	}
	
	
	/**
	 * save the SVG object to an image and send back to the user,
	 * then the user can save the image locally
	 */
	public static class SaveImageServlet extends HttpServlet {
		/**
	 * 
	 */
		private static final long serialVersionUID = 1L;

		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			doGet(request,response);
		}
		
		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {

			String tokenData = (String) request.getSession().getAttribute(
					"token");
			if (tokenData == null) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.getWriter().print(
						GSON.toJson("Current user not connected."));
				return;
			}
	        // Create the transcoder input.
	        String svg = request.getParameter("data");
	        
	        InputStream inputStream = new ByteArrayInputStream(svg.getBytes());
	        OutputStream outputStream = response.getOutputStream();
	        
	        response.setContentType("image/" + "jpeg");
	        response.setHeader("Content-Disposition", "attachment; filename=\"historyflow.svg\"");
	        
	        IOUtils.copy(inputStream, outputStream,
					true);
	        
	        outputStream.close();
	        /**
	         * Code to translate the SVG to PNG or JPEG, supper slow and messy text. 
	         * Couldn't find a way to bypass it. So for now, only support SVG export.
	         * /
	        /*
	        Document doc = getDocument(inputStream);
	        
	        TranscoderInput input_svg_image = new TranscoderInput(doc);
	        TranscoderOutput output_jpg_image = new TranscoderOutput(outputStream);
	        
	        try {
	            Transcoder transcoder = getTranscoder("jpeg", new Float(.9));
	            
	            response.setContentType("image/" + "jpeg");
		        response.setHeader("Content-Disposition", "attachment; filename=\"historyflow.jpg\"");
		        
	            transcoder.transcode(input_svg_image, output_jpg_image);
	        } catch (TranscoderException e) {
	            e.printStackTrace();
	        }
	        finally{
	        	outputStream.close();
	        	inputStream.close();
	        }
	        */
	        
			return;

		}
		/**
		 * function to support transcode svg to png/jpeg
		 * @param inputStream
		 * @return
		 * @throws IOException
		 *
        private Document getDocument(InputStream inputStream) throws IOException {
            String parser = XMLResourceDescriptor.getXMLParserClassName();
            SAXSVGDocumentFactory f = new SAXSVGDocumentFactory(parser);
            Document doc = f.createDocument("http://www.w3.org/2000/svg",
                    inputStream);
            return doc;
        }
        /**
         * function to support transcode svg to png/jpeg
         * @param transcoderType
         * @param keyQuality
         * @return
         *
        private Transcoder getTranscoder(String transcoderType, float keyQuality) {
            Transcoder transcoder = null;
            if (transcoderType.equals("jpeg")) {
                transcoder = getJPEGTranscoder(keyQuality);
            } else if (transcoderType.equals("png")) {
                transcoder = getPNGTranscoder();
            }
            return transcoder;
        }
        /**
         * function to support transcode svg to png/jpeg
         * @param keyQuality
         * @return
         *
        private JPEGTranscoder getJPEGTranscoder(float keyQuality) {
            JPEGTranscoder jpeg = new JPEGTranscoder();
            jpeg.addTranscodingHint(JPEGTranscoder.KEY_QUALITY, new Float(
                    keyQuality));
            return jpeg;
        }
        /**
         * function to support transcode svg to png/jpeg
         * @return
         *
        private PNGTranscoder getPNGTranscoder() {
            return new PNGTranscoder();
        }
        */
	}
}
