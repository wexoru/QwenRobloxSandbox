#pragma once

#include <Windows.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

#include "zstd.h"
#include "xxhash.h"

#include "BytecodeBuilder.h"
#include "BytecodeUtils.h"
#include "Compiler.h"

using JobOriginalVF = uintptr_t(__fastcall*)(uintptr_t A1, uintptr_t A2, uintptr_t A3);

static JobOriginalVF OriginalVF = {};
static std::vector<std::string> ScriptQueue;

// Logging functionality
namespace logger {
    enum class LogLevel {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3
    };

    inline std::string getCurrentTime() {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
        return std::string(buffer);
    }

    inline void log(LogLevel level, const std::string& message) {
        std::string levelStr;
        switch (level) {
            case LogLevel::DEBUG: levelStr = "DEBUG"; break;
            case LogLevel::INFO: levelStr = "INFO"; break;
            case LogLevel::WARNING: levelStr = "WARNING"; break;
            case LogLevel::ERROR: levelStr = "ERROR"; break;
        }

        std::string logMessage = "[" + getCurrentTime() + "] [" + levelStr + "] " + message + "\n";
        
        // Write to console
        std::cout << logMessage << std::flush;
        
        // Write to file
        std::ofstream logFile("executor.log", std::ios_base::app);
        logFile << logMessage;
        logFile.close();
    }

    inline void debug(const std::string& message) { log(LogLevel::DEBUG, message); }
    inline void info(const std::string& message) { log(LogLevel::INFO, message); }
    inline void warning(const std::string& message) { log(LogLevel::WARNING, message); }
    inline void error(const std::string& message) { log(LogLevel::ERROR, message); }
}

class bytecode_encoder_t : public Luau::BytecodeEncoder {
	inline void encode(uint32_t* data, size_t count) override {
		for (auto i = 0u; i < count;) {
			auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
			i += Luau::getOpLength(LuauOpcode(opcode));
			opcode *= 227;
		}
	}
};

std::string Compress(const std::string Bytecode) {
    size_t DataSize = Bytecode.size();
    size_t MaxSize = ZSTD_compressBound(DataSize);
    std::vector<char> Buffer(MaxSize + 8);

    memcpy(Buffer.data(), "RSB1", 4);
    memcpy(Buffer.data() + 4, &DataSize, sizeof(DataSize));

    size_t CompressedSize = ZSTD_compress(Buffer.data() + 8, MaxSize, Bytecode.data(), DataSize, ZSTD_maxCLevel());
    size_t TotalSize = CompressedSize + 8;

    uint32_t Key = XXH32(Buffer.data(), TotalSize, 42);
    uint8_t* KeyBytes = (uint8_t*)&Key;

    for (size_t i = 0; i < TotalSize; ++i) Buffer[i] ^= KeyBytes[i % 4] + i * 41;

    return std::string(Buffer.data(), TotalSize);
}

std::string Compile(const std::string& source)
{
    static bytecode_encoder_t encoder = bytecode_encoder_t();
    const std::string bytecode = Luau::compile(source, {}, {}, &encoder);

    if (bytecode[0] == '\0') {
        std::string bytecodeP = bytecode;
        bytecodeP.erase(std::remove(bytecodeP.begin(), bytecodeP.end(), '\0'), bytecodeP.end());
    }

    return Compress(bytecode);
}


#define REBASE(x) x + (uintptr_t)(GetModuleHandleA(nullptr));

uintptr_t state;

uintptr_t maxCaps = ~0ULL;

namespace offsets
{
	const uintptr_t JobToScriptContext = 0x3B0;
	const uintptr_t jobStart = 0x1D0;
	const uintptr_t jobEnd = 0x1D8;
	const uintptr_t jobName = 0x18;
	const uintptr_t getGlobalOffset = 0x140;
	const uintptr_t decryptStateOffset = 0x88;
	const uintptr_t setOp = 0x20;
}

namespace internalOffsets
{
	const uintptr_t Print = REBASE(0x14C8360);
	const uintptr_t TaskDefer = REBASE(0xF5DB40);
	const uintptr_t LuaVMLoad = REBASE(0xAD32E0);
	const uintptr_t GetGlobalState = REBASE(0xD2F660);
	const uintptr_t DecryptLuaState = REBASE(0xAD0240);
	const uintptr_t RawScheduler = REBASE(0x65DDF18);
}

namespace functions
{
	uintptr_t getScheduler()
	{
		return *(uintptr_t*)(internalOffsets::RawScheduler);
	}

	void settop(uintptr_t state)
	{
		*(uintptr_t*)(state + offsets::setOp) -= 0x10;
	}

	using _Print = uintptr_t(__fastcall*)(uintptr_t, const char*, ...);
	auto Print = (_Print)(internalOffsets::Print);

	using _GetGlobalState = uintptr_t(__fastcall*)(uintptr_t, uintptr_t*, uintptr_t*);
	auto GetGlobalState = (_GetGlobalState)(internalOffsets::GetGlobalState);

	using _DecryptState = uintptr_t(__fastcall*)(uintptr_t);
	auto DecryptState = (_DecryptState)(internalOffsets::DecryptLuaState);

	using _LuaVMLoad = int(__fastcall*)(uintptr_t, void*, const char*, int);
	auto LuaVMLoad = (_LuaVMLoad)(internalOffsets::LuaVMLoad);

	using _TaskDefer = uintptr_t(__fastcall*)(uintptr_t);
	auto TaskDefer = (_TaskDefer)(internalOffsets::TaskDefer);

	void setIdentity(uintptr_t state, uintptr_t level, uintptr_t caps)
	{
		uintptr_t userdata = *(uintptr_t*)(state + 0x78);

		uintptr_t* identity = (uintptr_t*)(userdata + 0x30);
		uintptr_t* capability = (uintptr_t*)(userdata + 0x48);

		*identity = level;
		*capability = caps;
	}
}

namespace scheduler
{
	std::vector<uintptr_t> getJobs()
	{
		std::vector<uintptr_t> jobs;

		uintptr_t scheduler = functions::getScheduler();

		uintptr_t start = *(uintptr_t*)(scheduler + offsets::jobStart);
		uintptr_t end = *(uintptr_t*)(scheduler + offsets::jobEnd);

		for (auto i = start; i < end; i+=0x10)
		{
			jobs.push_back(*(uintptr_t*)i);
		}

		return jobs;
	}

	uintptr_t getJobByName(std::string name)
	{
		for (auto job : scheduler::getJobs())
		{
			std::string jobName = *(std::string*)(job + offsets::jobName);

			if (jobName == name)
			{
				return job;
			}
		}

		return 0;
	}

	uintptr_t getScriptContext()
	{
		auto whsj = getJobByName("WaitingHybridScriptsJob");
		auto scriptContext = *(uintptr_t*)(whsj + offsets::JobToScriptContext);

		return scriptContext;
	}
}

namespace executor
{
	void executeScript(std::string script)
	{
		logger::debug("Executing script: " + script.substr(0, std::min((size_t)50, script.length())) + (script.length() > 50 ? "..." : ""));
		
		auto compiledAndCompressed = Compile(script);

		if (functions::LuaVMLoad(state, &compiledAndCompressed, "=Executor", 0) != 0)
		{
			logger::error("Error while executing script");
			functions::Print(3LL, "Error while executing...");
			functions::settop(state);
			return;
		}

		functions::TaskDefer(state);
		functions::settop(state);
		logger::debug("Script executed successfully");
		return;
	}

	uintptr_t Cycle(uintptr_t A1, uintptr_t A2, uintptr_t A3) {
		if (!state) return OriginalVF(A1, A2, A3);

		if (!ScriptQueue.empty()) {
			std::string Script = ScriptQueue.front();
			ScriptQueue.erase(ScriptQueue.begin());

			if (!Script.empty())
				executeScript(Script);
		}

		return OriginalVF(A1, A2, A3);
	}

	void HookJob(const std::string& Name) {
		uintptr_t Job = scheduler::getJobByName(Name);
		if (!Job) return;

		void** VTable = new void* [25]();
		memcpy(VTable, *(void**)Job, sizeof(uintptr_t) * 25);

		OriginalVF = (JobOriginalVF)VTable[2];
		VTable[2] = Cycle;

		*(void**)Job = VTable;
	}

	void initialize()
	{
		logger::info("Initializing executor...");
		auto scriptContext = scheduler::getScriptContext();
		if (!scriptContext) {
			logger::error("Failed to get script context");
			return;
		}
		logger::debug("Got script context: 0x" + std::to_string(scriptContext));

		uintptr_t x = 0;

		auto encryptedState = functions::GetGlobalState(scriptContext + offsets::getGlobalOffset, &x, &x);
		if (!encryptedState) {
			logger::error("Failed to get encrypted state");
			return;
		}
		logger::debug("Got encrypted state: 0x" + std::to_string(encryptedState));

		auto decryptedState = functions::DecryptState(encryptedState + offsets::decryptStateOffset);
		if (!decryptedState) {
			logger::error("Failed to decrypt state");
			return;
		}
		logger::debug("Got decrypted state: 0x" + std::to_string(decryptedState));

		state = decryptedState;

		functions::setIdentity(state, 8, maxCaps);
		logger::info("Executor initialized successfully with identity 8");
	}

	void addScript(std::string script)
	{
		logger::debug("Adding script to queue: " + script.substr(0, std::min((size_t)50, script.length())) + (script.length() > 50 ? "..." : ""));
		ScriptQueue.push_back(script);
		logger::info("Script queue size: " + std::to_string(ScriptQueue.size()));
	}
}
