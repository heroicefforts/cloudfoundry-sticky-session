package com.iamjambay.cloudfoundry.stickysession;


import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


public class MainServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;

	private static int stickyCount = 0;
	
    public MainServlet() {
    }

	protected void printCookies(HttpServletRequest request, HttpServletResponse response, PrintWriter writer) throws ServletException, IOException {
		Cookie[] cookies = request.getCookies();
		boolean sticky = false;
		boolean sessionWasNull = false;
		String sessionValue = null;
		
		if ("true".equals(request.getParameter("sticky"))) {
			HttpSession session = request.getSession( true );
			sessionValue = (String) session.getAttribute("value");
			if(sessionValue == null) {
				sessionWasNull = true;
				session.setAttribute("value", "happy");
			}
			++stickyCount;
			sticky = true;
		}
		
		if( cookies != null )
		{
			writer.println( "Cookies: " + "<br/>");
        	for (int i = 0; i < cookies.length; i++) {
        		String name = cookies[i].getName();
            	String value = cookies[i].getValue();
				if ( "__VCAP_ID__".equals(name) )
					sticky = true;
            	writer.println("  Name: " + name + "<br/>" );
            	writer.println("  Value: " + value + "<br/>");
  			}
        	writer.println("<br/><br/>");
		}

		if(sticky) {
			writer.print("Sticky session <b>should</b> be enabled");
			
			if(stickyCount > 1 && sessionWasNull) //session created in a past request and there was nothing in session
				writer.print(", but isn't (BOOOOO! ;D )");
			
			writer.println(". Refreshing the browser <b>should</b> keep routing to the same app instance.<br/><br/>");
		}
		else writer.println("Sticky session is NOT enabled. Refreshing the browser should route to random app instances.<br/><br/><a href='?sticky=true'>start a sticky session</a>"+ "<br/><br/>");

		if(sessionValue != null)
			writer.println("Session value is:  " + sessionValue);
		else
			writer.println("There was no session.  New session created and value set to:  happy.");
		writer.println("<br/>");
		writer.println("<br/>");
    }

	protected void printAppEnv(HttpServletRequest request, HttpServletResponse response, PrintWriter writer) throws ServletException, IOException {
		writer.println("VCAP_APPLICATION env var: " + System.getenv("VCAP_APPLICATION") + "<br/>" );
		writer.println("<br/>");
        writer.println("Port: " + System.getenv("PORT")+ "<br/>");
    }

	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		response.setStatus(200);
		PrintWriter writer = response.getWriter();

		if ("true".equals(request.getParameter("shutdown"))) {
			System.exit(1);
		}
		writer.println("<a href='?shutdown=true'>kill this app instance</a>"+ "<br/><br/>");
		
		printCookies(request, response, writer);
		printAppEnv(request, response, writer);

		writer.close();
	}
}
