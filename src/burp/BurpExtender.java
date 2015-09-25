package burp;

import java.util.*;
import java.awt.event.*;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory
{
	private IExtensionHelpers helpers;

	private final static String NAME = "Copy as requests";

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		helpers = callbacks.getHelpers();
		callbacks.setExtensionName(NAME);
		callbacks.registerContextMenuFactory(this);
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		final IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		if (messages == null || messages.length == 0) return null;
		JMenuItem i = new JMenuItem(NAME);
		i.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				copyMessages(messages);
			}
		});
		return Collections.singletonList(i);
	}

	private void copyMessages(IHttpRequestResponse[] messages) {
		StringBuilder py = new StringBuilder("import requests\n");

		for (IHttpRequestResponse message : messages) {
			IRequestInfo ri = helpers.analyzeRequest(message);
			byte[] req = message.getRequest();
			py.append("\nrequests.");
			py.append(ri.getMethod().toLowerCase());
			py.append("(\"");
			py.append(escapeQuotes(ri.getUrl().toString()));
			py.append("\", headers={");
			boolean firstHeader = true;
			for (String header : ri.getHeaders()) {
				if (header.startsWith("Host:")) continue;
				header = escapeQuotes(header);
				int colonPos = header.indexOf(':');
				if (colonPos == -1) continue;
				if (firstHeader) {
					firstHeader = false;
					py.append('"');
				} else {
					py.append(", \"");
				}
				py.append(header, 0, colonPos);
				py.append("\": \"");
				py.append(header, colonPos + 2, header.length());
				py.append('"');
			}
			py.append('}');
			int bo = ri.getBodyOffset();
			if (bo < req.length - 1) {
				py.append(", data=");
				if (ri.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
					py.append('{');
					boolean firstKey = true;
					for (String param : new String(req, bo, req.length - bo).split("&")) {
						if (firstKey) {
							firstKey = false;
							py.append('"');
						} else {
							py.append(", \"");
						}
						String[] parts = param.split("=", 2);
						py.append(escapeQuotes(helpers.urlDecode(parts[0])));
						py.append("\": \"");
						py.append(escapeQuotes(helpers.urlDecode(parts[1])));
						py.append('"');
					}
					py.append('}');
				} else {
					py.append('"');
					py.append(escapeQuotes(new String(req, bo, req.length - bo)));
					py.append('"');
				}
			}
			py.append(')');
		}

		System.err.println(py.toString()); // TODO clipboard
	}

	private String escapeQuotes(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"")
			.replace("\n", "\\n").replace("\r", "\\r");
	}
}
