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
		// TODO
	}
}
