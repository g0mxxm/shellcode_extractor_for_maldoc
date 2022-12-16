var OleConvertOLESTREAMToIStorage = Module.findExportByName("Ole32.dll", "OleConvertOLESTREAMToIStorage");
console.log("[+] OleConvertOLESTREAMToIStorage: " + OleConvertOLESTREAMToIStorage);

Interceptor.attach(OleConvertOLESTREAMToIStorage, {
    onEnter: function (args) {
        console.log("[+] arg[0]: " + args[0]);
        var addr_1 = args[0].add(8);
        var length = args[0].add(12).readU32();
        console.log("[+] addr_1: " + addr_1);
        console.log("[+] length: " + length);
        var addr_2 = addr_1.readPointer();
        console.log("[+] addr_2: " + addr_2);
        var addr_ole = addr_2.readPointer();
        console.log("[+] addr_ole: " + addr_ole);
        console.log(hexdump(addr_ole, {
            offset: 0,
            length: 200,
            header: true,
            ansi: false
        }));
        var pattern = "D0 CF 11 E0 A1 B1 1A E1";
        //var ole_memory = addr_ole.readByteArray(length);
        //var file = new File("C:\\Users\\g0mx\\Desktop\\ole_file","wb");
        //file.write(ole_memory);
        //file.close();
        Memory.scan(addr_ole, length, pattern, {
            onMatch: function(address, size) {
                console.log("[+] pattern(D0 CF 11 E0 A1 B1 1A E1) addr is " + address);
                var addr_ole_final = address;
                var length_final = length - (addr_ole_final - addr_ole);
                var ole_memory = addr_ole_final.readByteArray(length_final);
                var file = new File("C:\\Users\\g0mx\\Desktop\\ole_file","wb");
                file.write(ole_memory);
                file.close();
            },
            onError: function(reason) {
                console.log("Failed to found the pattern you needed!");
            }
        })
    }
});