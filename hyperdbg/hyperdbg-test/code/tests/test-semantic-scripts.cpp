/**
 * @file test-semantic-scripts.cpp
 * @author Sina Karvandi (sina@hyperdbg.org)
 * @brief Perform test on semantic scripts
 * @details
 * @version 0.11
 * @date 2024-08-16
 *
 * @copyright This project is released under the GNU Public License v3.
 *
 */
#include "pch.h"

namespace fs = std::filesystem;

static std::mutex              SemanticOutputMutex;
static std::condition_variable SemanticOutputChanged;
static std::string             SemanticOutput;

static VOID
CaptureSemanticOutput(CHAR * Message)
{
    if (!Message)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> Lock(SemanticOutputMutex);
        SemanticOutput.append(Message);
    }
    SemanticOutputChanged.notify_all();
}

static BOOLEAN
HasAllExpectedSemanticOutput(const std::string & Output)
{
    if (Output.find("was failed") != std::string::npos)
    {
        return FALSE;
    }

    std::set<UINT32> SuccessfulCases;
    std::regex       SuccessPattern("test case ([0-9]+) was successful");
    for (std::sregex_iterator Match(Output.begin(), Output.end(), SuccessPattern), End;
         Match != End;
         ++Match)
    {
        SuccessfulCases.insert((UINT32)std::stoul((*Match)[1].str()));
    }

    return SuccessfulCases.size() == 83 &&
           *SuccessfulCases.begin() == 0 &&
           *SuccessfulCases.rbegin() == 82 &&
           Output.find("floating point: 11.500000 0.500000 0.500000 11.000000 0.789000") != std::string::npos &&
           Output.find("negative floating point: -11.500000 -0.500000 -0.789000 -0.000000") != std::string::npos &&
           Output.find("runtime negative floating point: -0.789000") != std::string::npos &&
           Output.find("runtime positive floating point: 0.500000") != std::string::npos &&
           Output.find("floating arithmetic was successful") != std::string::npos &&
           Output.find("floating arithmetic: 12.000000 11.000000 3.000000 3.000000") != std::string::npos &&
           Output.find("double arithmetic: 1.000000 3.500000 5.000000 2.250000") != std::string::npos &&
           Output.find("mixed and precedence: 1.750000 7.000000 -6.000000") != std::string::npos;
}

static BOOLEAN
SemanticRunFinishedOrFailed(const std::string & Output)
{
    return Output.find("was failed") != std::string::npos || HasAllExpectedSemanticOutput(Output);
}

/**
 * @brief Read directory of semantic test cases and run each of them
 *
 * @param ScriptSemanticPath Path to the semantic test cases
 *
 * @return BOOLEAN TRUE if all files were read and submitted successfully
 */
BOOLEAN
ReadDirectoryAndTestSemanticTestCases(const CHAR * ScriptSemanticPath)
{
    //
    // Iterate through the directory
    //
    try
    {
        std::vector<fs::path> TestFiles;
        for (const auto & Entry : fs::directory_iterator(ScriptSemanticPath))
        {
            if (Entry.is_regular_file() && Entry.path().extension() == ".ds")
            {
                TestFiles.push_back(Entry.path());
            }
        }

        std::sort(TestFiles.begin(), TestFiles.end());
        if (TestFiles.empty())
        {
            std::cerr << "No semantic .ds files were found in: " << ScriptSemanticPath << std::endl;
            return FALSE;
        }

        for (const auto & FilePath : TestFiles)
        {
            std::ifstream File(FilePath, std::ios::binary);
            if (!File)
            {
                std::cerr << "Could not open file: " << FilePath.string() << std::endl;
                return FALSE;
            }

            std::string Content((std::istreambuf_iterator<char>(File)),
                                std::istreambuf_iterator<char>());
            if (File.bad())
            {
                std::cerr << "Could not read file: " << FilePath.string() << std::endl;
                return FALSE;
            }

            std::cout << "Executing file " << FilePath.filename().string() << std::endl;
            if (hyperdbg_u_run_command(Content.data()) != 0)
            {
                std::cerr << "Command execution failed for: " << FilePath.string() << std::endl;
                return FALSE;
            }
        }
    }
    catch (const fs::filesystem_error & e)
    {
        std::cerr << "Filesystem error: " << e.what() << std::endl;
        return FALSE;
    }

    return TRUE;
}

/**
 * @brief Test semantic scripts
 *
 * @return BOOLEAN
 */
BOOLEAN
TestSemanticScripts()
{
    CHAR  dirPath[MAX_PATH] = {0};

    //
    // Parse the semantic script test cases from the file
    // Setup the path for the filenames
    //
    if (!hyperdbg_u_setup_path_for_filename(SCRIPT_SEMANTIC_TEST_CASE_DIRECTORY, dirPath, MAX_PATH, FALSE))
    {
        //
        // Error could not find the test case files
        //
        cout << "[-] Could not find the test case files" << endl;
        return FALSE;
    }

    //
    // Connect to the debugger
    //
    if (!hyperdbg_u_connect_remote_debugger_using_named_pipe(TEST_DEFAULT_NAMED_PIPE, TRUE))
    {
        cout << "[-] Could not connect to the debugger" << endl;
        return FALSE;
    }

    {
        std::lock_guard<std::mutex> Lock(SemanticOutputMutex);
        SemanticOutput.clear();
    }
    hyperdbg_u_set_text_message_callback((PVOID)CaptureSemanticOutput);

    BOOLEAN TestResult = ReadDirectoryAndTestSemanticTestCases(dirPath);
    if (TestResult)
    {
        std::unique_lock<std::mutex> Lock(SemanticOutputMutex);
        BOOLEAN Completed = SemanticOutputChanged.wait_for(
            Lock,
            std::chrono::seconds(60),
            [] { return SemanticRunFinishedOrFailed(SemanticOutput); });

        TestResult = Completed &&
                     SemanticOutput.find("was failed") == std::string::npos &&
                     HasAllExpectedSemanticOutput(SemanticOutput);
        if (!TestResult)
        {
            std::cerr << "Semantic output was incomplete, timed out, or contained a failure.\n"
                      << SemanticOutput << std::endl;
        }
    }

    hyperdbg_u_unset_text_message_callback();

    //
    // Close the connection
    //
    hyperdbg_u_debug_close_remote_debugger();

    return TestResult;
}
