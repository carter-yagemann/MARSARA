package tracker;

import org.apache.commons.cli.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Configuration {
    Options commandLineOptions;
    public boolean removeModules = false;
    public boolean removeNetworks = false;
    public boolean runTests = false;
    public String runApts = null;
    public boolean runBenigns = false;
    public String outputDir = "NAN";


    private static final Logger logger = LoggerFactory.getLogger(Configuration.class);

    public void parseCommandLineArgs(String[] args) {
        if (commandLineOptions == null) {
            commandLineOptions = getCommandLineOptions();
        }
        CommandLineParser parser = new GnuParser();
        try {
            CommandLine commandLineArgs = parser.parse(commandLineOptions, args);
            if (commandLineArgs.hasOption("h")) {
                help();
                System.exit(0);
            }
            // Debugging only: Removing all the modules from graph
            removeModules = commandLineArgs.hasOption("rmm");
            // Debugging only: Removing all the registeries from graph
            removeNetworks = commandLineArgs.hasOption("rmn");
            // Generate provenance graph database for  MITRE tests
            runTests = commandLineArgs.hasOption("test");
            // Generate provenance graph database for  APTs
            runApts = commandLineArgs.getOptionValue("apt", runApts);
            // Generate provenance graph database for  benign dataset
            runBenigns = commandLineArgs.hasOption("benign");

            outputDir = commandLineArgs.getOptionValue("o", outputDir);


        } catch (ParseException e) {
            e.printStackTrace();
        }
        logger.info("Removing Modules: " + removeModules);
        logger.info("Removing Registers: " + removeNetworks);
        logger.info("Running Tests: " + runTests);
        logger.info("Running Apts: " + runApts);
        logger.info("Running Benigns: " + runBenigns);
        logger.info("Output Directory: " + runBenigns);
    }

    private Options getCommandLineOptions() {
        Options options = new Options();
        options.addOption("rmm", "remove-module", false,
                "Remove modules from the graph");
        options.addOption("rmn", "remove-network", false,
                "Remove network nodes from graph");
        options.addOption("test", "tests", false,
                "Run tests");
        options.addOption("apt", "apt", true,
                "Specify which apt to run");
        options.addOption("benign", "benigns", false,
                "Run benign");
        options.addOption("o", "output", true,
                "Graph database directory");
        return options;
    }

    public void help() {
        if (commandLineOptions == null) {
            commandLineOptions = getCommandLineOptions();
        }
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("FDR_TRACKER", commandLineOptions);
    }
}
