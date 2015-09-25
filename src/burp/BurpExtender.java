package burp;

import java.util.*;
import java.awt.datatransfer.*;
import java.awt.event.*;
import java.awt.Toolkit;
import javax.swing.JMenuItem;

public class BurpExtender implements IBurpExtender, IContextMenuFactory, ClipboardOwner
{
	private IExtensionHelpers helpers;

	private final static String NAME = "Copy as requests";
	private final static String[] PYTHON_ESCAPE = new String[256];

	static {
		for (int i = 0x00; i <= 0xFF; i++) PYTHON_ESCAPE[i] = String.format("\\x%02x", i);
		for (int i = 0x20; i < 0x80; i++) PYTHON_ESCAPE[i] = String.valueOf((char)i);
		PYTHON_ESCAPE['\n'] = "\\n";
		PYTHON_ESCAPE['\r'] = "\\r";
		PYTHON_ESCAPE['\t'] = "\\t";
		PYTHON_ESCAPE['"'] = "\\\"";
		PYTHON_ESCAPE['\\'] = "\\\\";
	}

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
		StringBuilder py = new StringBuilder("import requests");
		int i = 0;

		for (IHttpRequestResponse message : messages) {
			IRequestInfo ri = helpers.analyzeRequest(message);
			byte[] req = message.getRequest();
			String prefix = "burp" + i++ + "_";
			py.append("\n\n").append(prefix).append("url = \"");
			py.append(escapeQuotes(ri.getUrl().toString()));
			py.append("\"\n").append(prefix).append("headers = {");
			processHeaders(py, ri.getHeaders());
			py.append('}');
			boolean bodyExists = processBody(prefix, py, req, ri);
			py.append("\nrequests.");
			py.append(ri.getMethod().toLowerCase());
			py.append('(').append(prefix).append("url, headers=");
			py.append(prefix).append("headers");
			if (bodyExists) py.append(", data=").append(prefix).append("data");
			py.append(')');
		}

		Toolkit.getDefaultToolkit().getSystemClipboard()
			.setContents(new StringSelection(py.toString()), this);
	}

	private static void processHeaders(StringBuilder py, List<String> headers) {
		boolean firstHeader = true;
		for (String header : headers) {
			if (header.toLowerCase().startsWith("host:")) continue;
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
	}

	private boolean processBody(String prefix, StringBuilder py,
			byte[] req, IRequestInfo ri) {
		int bo = ri.getBodyOffset();
		if (bo >= req.length - 2) return false;
		py.append('\n').append(prefix).append("data=");
		if (ri.getContentType() == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
			py.append('{');
			boolean firstKey = true;
			int keyStart = bo, keyEnd = -1;
			for (int pos = bo; pos < req.length; pos++) {
				byte b = req[pos];
				if (keyEnd == -1) {
					if (b == (byte)'=') {
						if (pos == req.length - 1) {
							if (!firstKey) py.append(", ");
							escapeUrlEncodedBytes(req, py, keyStart, pos);
							py.append(": ''");
						} else {
							keyEnd = pos;
						}
					}
				} else if (b == (byte)'&' || pos == req.length - 1) {
					if (firstKey) firstKey = false; else py.append(", ");
					escapeUrlEncodedBytes(req, py, keyStart, keyEnd);
					py.append(": ");
					escapeUrlEncodedBytes(req, py, keyEnd + 1,
							pos == req.length - 1 ? req.length : pos);
					keyEnd = -1;
					keyStart = pos + 1;
				}
			}
			py.append('}');
		} else {
			escapeBytes(req, py, bo, req.length);
		}
		return true;
	}

	private static String escapeQuotes(String value) {
		return value.replace("\\", "\\\\").replace("\"", "\\\"")
			.replace("\n", "\\n").replace("\r", "\\r");
	}

	private void escapeUrlEncodedBytes(byte[] input, StringBuilder output,
			int start, int end) {
		if (end > start) {
			byte[] dec = helpers.urlDecode(Arrays.copyOfRange(input, start, end));
			escapeBytes(dec, output, 0, dec.length);
		} else {
			output.append("''");
		}
	}

	private static void escapeBytes(byte[] input, StringBuilder output,
			int start, int end) {
		output.append('"');
		for (int pos = start; pos < end; pos++) {
			output.append(PYTHON_ESCAPE[input[pos] & 0xFF]);
		}
		output.append('"');
	}

	@Override
	public void lostOwnership(Clipboard aClipboard, Transferable aContents) {}
}
