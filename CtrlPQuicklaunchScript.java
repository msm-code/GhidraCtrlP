import ghidra.app.script.GhidraScript;
import java.awt.*;
import javax.swing.JFrame;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.app.services.*;
import ghidra.framework.plugintool.*;
import ghidra.util.task.*;

public class CtrlPQuicklaunchScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        String expectedName = "CtrlP - " + getCurrentProgram().getDomainFile().toString();
        for (Window window : Window.getWindows()) {
            if (window instanceof JFrame) {
                JFrame frame = (JFrame) window;
                if (frame.getTitle().equals(expectedName) && frame.isDisplayable()) {
                    if (frame.isShowing()) {
                        frame.setVisible(false);
                    } else {
                        frame.setVisible(true);
                    }
                    return;
                }
            }
        }

        println("CtrlP window not found, launching it: " + expectedName);
        ConsoleService consoleService = state.getTool().getService(ConsoleService.class);
        ResourceFile script = GhidraScriptUtil.findScriptByName("ctrlp.py");
        if (script == null) {
            println("ctrl.py script not found - install it, or run it manually if you changed the filename");
            return;
        }

        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(script);
        GhidraScript scriptInstance = provider.getScriptInstance(script, consoleService.getStdOut());
        scriptInstance.execute(state, TaskMonitor.DUMMY, consoleService.getStdOut());
    }
}
