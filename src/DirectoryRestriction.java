import java.io.File;
import java.io.IOException;

import javax.swing.filechooser.FileSystemView;

public class DirectoryRestriction extends FileSystemView{

	 private final File[] rootDirectories;

	    DirectoryRestriction(File rootDirectory)
	    {
	        this.rootDirectories = new File[] {rootDirectory};
	    }

	    DirectoryRestriction(File[] rootDirectories)
	    {
	        this.rootDirectories = rootDirectories;
	    }

	    @Override
	    public File createNewFolder(File containingDir) throws IOException
	    {       
	        throw new UnsupportedOperationException("Unable to create directory");
	    }

	    @Override
	    public File[] getRoots()
	    {
	        return rootDirectories;
	    }

	    @Override
	    public boolean isRoot(File file)
	    {
	        for (File root : rootDirectories) {
	            if (root.equals(file)) {
	                return true;
	            }
	        }
	        return false;
	    }
	    
}
