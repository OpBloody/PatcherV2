import wx

plugin_name = "Test plugin"


def run_plugin():
    """Create a new window for the plugin."""
    frame = wx.Frame(None, title=plugin_name, size=(300, 200))
    panel = wx.Panel(frame)
    wx.StaticText(panel, label='Hello from plugin!', pos=(20, 20))
    frame.Show()
