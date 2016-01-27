__author__ = 'Robin'

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager

class FileMarkIngestModuleFactory(IngestModuleFactoryAdapter):

    moduleName = "File Mark"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Finds Event Logs, Memory, and Registry files and marks as Interesting"

    def getModuleVersionNumber(self):
        return "1.0"

    def isFileIngestModuleFactory(self):
        return True

    def createFileIngestModule(self, ingestOptions):
        return FileMarkIngestModule()

class FileMarkIngestModule(FileIngestModule):

    _logger = Logger.getLogger(FileMarkIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def startUp(self, context):
        pass

    def process(self, file):

        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False)):
            return IngestModule.ProcessResult.OK

        if (file.getNameExtension() == "evtx"):

            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                  FileMarkIngestModuleFactory.moduleName, "Event Logs")
            art.addAttribute(att)

            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkIngestModuleFactory.moduleName,
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        if (file.getName() == "pagefile.sys" or file.getName() == "hiberfil.sys" or file.getName() == "MEMORY.DMP"):

            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                  FileMarkIngestModuleFactory.moduleName, "Memory")
            art.addAttribute(att)

            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkIngestModuleFactory.moduleName,
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        if (file.getName() == "SYSTEM" or file.getName() == "SECURITY" or file.getName() == "SOFTWARE" or file.getName() == "SAM" or file.getName() == "NTUSER.DAT" or file.getName() == "UsrClass.dat" or file.getName() == "RecentFileCache.bcf" or file.getName() == "Amcache.hve"):

            art = file.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
            att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(),
                  FileMarkIngestModuleFactory.moduleName, "Registry")
            art.addAttribute(att)

            IngestServices.getInstance().fireModuleDataEvent(
                ModuleDataEvent(FileMarkIngestModuleFactory.moduleName,
                    BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT, None));

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        None
