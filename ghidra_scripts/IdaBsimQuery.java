// Query one function using Ghidra's BSim signature generator and database client.
// BSim query flow adapted from NSA Ghidra's QueryFunction.java (Apache-2.0).
//@category BSim

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.Iterator;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

public class IdaBsimQuery extends GhidraScript {
    private Function fromAddress(Address address) {
        Function function = currentProgram.getFunctionManager().getFunctionAt(address);
        return function != null ? function : currentProgram.getFunctionManager().getFunctionContaining(address);
    }

    private Function findFunction(String fileOffset, String rva, JsonObject result) throws Exception {
        if (!"-".equals(fileOffset)) {
            long offset = Long.parseUnsignedLong(fileOffset, 16);
            for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
                if (!block.isExecute()) {
                    continue;
                }
                for (MemoryBlockSourceInfo source : block.getSourceInfos()) {
                    Address mapped = source.locateAddressForFileOffset(offset);
                    if (mapped == null) {
                        continue;
                    }
                    Function function = fromAddress(mapped);
                    if (function != null) {
                        result.addProperty("mapped_by", "file_offset");
                        result.addProperty("exact_entry", function.getEntryPoint().equals(mapped));
                        return function;
                    }
                }
            }
        }

        long offset = Long.parseUnsignedLong(rva, 16);
        Address address = currentProgram.getImageBase().addNoWrap(offset);
        Function function = fromAddress(address);
        if (function != null) {
            result.addProperty("mapped_by", "rva");
            result.addProperty("exact_entry", function.getEntryPoint().equals(address));
        }
        return function;
    }

    private void queryFunction(String databaseUrl, String fileOffset, String rva,
            double similarity, double confidence, int maxMatches, JsonObject result)
            throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Headless script has no current program");
        }
        Function function = findFunction(fileOffset, rva, result);
        if (function == null) {
            throw new IllegalArgumentException("No Ghidra function at IDA file offset " + fileOffset
                + " or RVA " + rva + "; compare function boundaries in both tools");
        }
        result.addProperty("query_function", function.getName());
        result.addProperty("ghidra_entry", function.getEntryPoint().toString());
        if (!Double.isFinite(similarity) || similarity < 0 || similarity > 1 ||
            !Double.isFinite(confidence) || confidence < 0 || maxMatches < 1 || maxMatches > 1000) {
            throw new IllegalArgumentException("Invalid BSim search options");
        }

        URL url = BSimClientFactory.deriveBSimURL(databaseUrl);
        try (FunctionDatabase database = BSimClientFactory.buildClient(url, false)) {
            if (!database.initialize()) {
                throw new IllegalStateException("BSim database: " + database.getLastError().message);
            }
            GenSignatures signatures = new GenSignatures(false);
            try {
                signatures.setVectorFactory(database.getLSHVectorFactory());
                signatures.openProgram(currentProgram, null, null, null, null, null);
                signatures.scanFunction(function);

                DescriptionManager manager = signatures.getDescriptionManager();
                QueryNearest query = new QueryNearest();
                query.manage = manager;
                query.max = maxMatches;
                query.thresh = similarity;
                query.signifthresh = confidence;
                ResponseNearest response = query.execute(database);
                if (response == null) {
                    throw new IllegalStateException("BSim query: " + database.getLastError().message);
                }

                JsonArray matches = new JsonArray();
                Iterator<SimilarityResult> results = response.result.iterator();
                while (results.hasNext()) {
                    SimilarityResult group = results.next();
                    Iterator<SimilarityNote> notes = group.iterator();
                    while (notes.hasNext()) {
                        SimilarityNote note = notes.next();
                        FunctionDescription match = note.getFunctionDescription();
                        ExecutableRecord executable = match.getExecutableRecord();
                        JsonObject row = new JsonObject();
                        row.addProperty("function", match.getFunctionName());
                        row.addProperty("executable", executable.getNameExec());
                        row.addProperty("md5", executable.getMd5());
                        row.addProperty("address", Long.toUnsignedString(match.getAddress(), 16));
                        row.addProperty("similarity", note.getSimilarity());
                        row.addProperty("significance", note.getSignificance());
                        row.addProperty("ingest_date", executable.getDate() != null &&
                            executable.getDate().getTime() > 0
                                ? DateTimeFormatter.ISO_INSTANT.format(executable.getDate().toInstant())
                                : "");
                        matches.add(row);
                    }
                }
                result.add("matches", matches);
                result.addProperty("ok", true);
            }
            finally {
                signatures.dispose();
            }
        }
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 7) {
            throw new IllegalArgumentException(
                "Expected database URL, file offset, RVA, similarity, confidence, max matches, output JSON path");
        }
        JsonObject result = new JsonObject();
        result.addProperty("ok", false);
        result.add("matches", new JsonArray());
        try {
            queryFunction(args[0], args[1], args[2], Double.parseDouble(args[3]),
                Double.parseDouble(args[4]), Integer.parseInt(args[5]), result);
        }
        catch (Exception exc) {
            result.addProperty("error", exc.toString());
            printerr("IDA BSim: " + exc);
        }
        Files.writeString(Path.of(args[6]), result.toString(), StandardCharsets.UTF_8);
    }
}
