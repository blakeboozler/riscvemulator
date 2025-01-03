import sys

##########################################################################################
#                                       YB-60 CLASS                                      #
##########################################################################################

class YB60:

    def __init__(self):
        self.memory = bytearray(1048576) # 1MB memory
        self.registers = [0]*32          # x0-x31 registers
        self.pc = 0                      # program counter

    def loadProgram(self, fileName):
        try:
            with open(fileName, 'r') as file:

                offsetExists = False

                for line in file:
                    line = line.strip()

                    if line.startswith(':'):  # begin parsing of Intel HEX Records
                        data = line[1:] # ignore the colon
                        byteCount = int(data[0:2], 16) # obtain byte count
                        adr = int(data[2:6], 16) # obtain address
                        adrHigh = int(data[2:4], 16) # left 2 bits of address (for ESA purposes)
                        adrLow = int(data[4:6], 16) # right 2 bits of address (for ESA purposes)
                        hexRecord = int(data[6:8], 16) # obtain HEX record
                        checkSum = int(data[-2:], 16) # obtain checksum
                        # obtains all databytes efficiently
                        dataBytes = [int(data[i:i+2], 16) for i in range(8, 8 + byteCount * 2, 2)]
                        
                        # calculating the checksum
                        calcCS = (-(byteCount + adrHigh + adrLow + hexRecord + sum(dataBytes)) & 0xFF) & 0xFF

                        if calcCS == checkSum: # verifying calculated checksum to given one

                            if hexRecord == 0x00:
                                for i, byteValue in enumerate(dataBytes):
                                    if offsetExists: # only after ESA records
                                        self.memory[adr+offset+i] = byteValue
                                        
                                    else:
                                        self.memory[adr+i] = byteValue
                                        
                            elif hexRecord == 0x02: # ESA Record
                                offset = ((dataBytes[0] << 8) | dataBytes[1]) << 4
                                offsetExists = True

                            elif hexRecord == 0x01: # EOF Record
                                pass

                            else:
                                print("Unsupported/invalid hex type - exiting program")
                                exit(2)
                            
                        else:
                            print("Format error input file:", fileName)
                            exit(2)
                        
                self.startMonitor()

        except FileNotFoundError:
            print("File not found:", fileName)
            exit(2)

    def displayMemory(self, adrStr):
        try:
            adr = int(adrStr, 16) # converting from a string
            if ((adr > 0xFFFFF) or (adr < 0)):
                print("Value", adrStr, "does not exist in memory")
                exit(2)

            data = []
            data.append(self.memory[adr])

            print(adrStr.zfill(5).upper(), " ".join([hex(d)[2:].zfill(2) for d in data]))

        except ValueError:
            print("Format error - enter a valid address/other command")

    def displayMemoryRange(self, startAdrStr, endAdrStr):
        try:
            startAdr = int(startAdrStr, 16)
            endAdr = int(endAdrStr, 16)
            
            if ((startAdr > 0xFFFFF) or (endAdr > 0xFFFFF) or (startAdr < 0) or (endAdr < 0)):
                print("One or both addresses exist outside of memory")
                exit(2)

            if startAdr <= endAdr:
                adr = startAdr
                data = []

                while adr <= endAdr:
                    strStart = hex(startAdr)[2:].zfill(5).upper() # crops "0x", fills zeroes in
                    data.append(self.memory[adr]) 
                    adr += 1

                    if len(data) == 8: # prints data in groups of 8 bytes
                        print(strStart, " ".join([hex(d)[2:].zfill(2) for d in data]).upper())
                        startAdr += 8
                        data = []

                if data: # prints out any remaining data
                    print(strStart, " ".join([hex(d)[2:].zfill(2) for d in data]).upper())

            else:
                print("Error - starting address <= ending address")

        except ValueError:
            print("Format error - enter valid hexadecimal memory addresses")

    def editMemory(self, editCmd):
        try:
            adrStr, dataStr = editCmd.split(":")
            adr = int(adrStr, 16)
            dataBytes = dataStr.split()

            if ((adr > 0xFFFFF) or (adr < 0)):
                print("Value", adrStr, "does not exist in memory")
                exit(2)

            for i, dataByteStr in enumerate(dataBytes):
                if((adr+i) > 0xFFFFF):
                    print("Editing extends outside of memory")
                    exit(2)
                self.memory[adr + i] = int(dataByteStr, 16)
                    
        except (ValueError, IndexError):
            print("Format error - enter valid hexademical address, a colon, then valid databytes")

    def runProgram(self, startAdrStr):
        self.registers = [0]*32 # x0-x31 registers
        self.registers[2] = 0x000FFFFF
        try:
            i = 0
            startAdr = int(startAdrStr, 16)
            if ((startAdr > 0xFFFFF) or (startAdr < 0x0)):
                print("Address", startAdrStr, "does not exist in memory")
                self.exitMonitor()

            self.pc = startAdr  # sets program counter to the provided starting address

            while True:
                inst = (self.memory[self.pc + 3] << 24) | (self.memory[self.pc + 2] << 16) | \
                            (self.memory[self.pc + 1] << 8) | self.memory[self.pc]
                inst32 = f"{inst:032b}"
                
                decoded = self.decodeInstruction(inst32)

                PC = hex(self.pc)[2:].zfill(5).upper()
                OPC = f"{inst:08x}".upper()
                decoded2 = self.getInstandReg(decoded, inst32)
                self.runInstruction(decoded2, inst32)

                if(i == 0):
                    print("    PC      OPC   INST  rd    rs1  rs2/imm       ")
                    i = i + 1
                print(f" {PC} {OPC} {decoded2}")
                
                if inst == 0x00100073: # EBREAK check
                    break
                
                if(not((inst32[-7:-2] == "11001") or (inst32[-7:-2] == "11000") \
                    or (inst32[-7:-2] == "01101") or (inst32[-7:2] == "00101") \
                        or (inst32[-7:-2] == "11011"))):
                    self.pc += 4 # increment program counter

        except ValueError:
            print("Error detected")

    def runProgramStep(self):
        
        try:
            i = 0
            if ((self.pc > 0xFFFFF) or (self.pc < 0x0)):
                print("Address", self.pc, "does not exist in memory")
                self.exitMonitor()

            inst = (self.memory[self.pc + 3] << 24) | (self.memory[self.pc + 2] << 16) | \
                        (self.memory[self.pc + 1] << 8) | self.memory[self.pc]
            inst32 = f"{inst:032b}"
            
            decoded = self.decodeInstruction(inst32)

            PC = hex(self.pc)[2:].zfill(5).upper()
            OPC = f"{inst:08x}".upper()
            decoded2 = self.getInstandReg(decoded, inst32)
            self.runInstruction(decoded2, inst32)

            if(i == 0):
                print("    PC      OPC   INST  rd    rs1  rs2/imm       ")
                i = i + 1
            print(f" {PC} {OPC} {decoded2}")
            
            if inst == 0x00100073: # EBREAK check
                breakpoint
            
            if(not((inst32[-7:-2] == "11001") or (inst32[-7:-2] == "11000") \
                or (inst32[-7:-2] == "01101") or (inst32[-7:2] == "00101") \
                    or (inst32[-7:-2] == "11011") or (inst32[-7:-2]) == "11001")):
                self.pc += 4 # increment program counter

        except ValueError:
            print("Error detected")

    def disassembleCode(self, startAdrStr):
        try:
            startAdr = int(startAdrStr, 16)
            self.pc = startAdr
            if ((startAdr > 0xFFFFF) or (startAdr < 0x0)):
                print("Address", startAdrStr, "does not exist in memory")
                self.exitMonitor()
            
            while True:
                inst = (self.memory[self.pc + 3] << 24) | (self.memory[self.pc + 2] << 16) | \
                            (self.memory[self.pc + 1] << 8) | self.memory[self.pc]
                
                decoded = self.decodeInstruction(f"{inst:032b}")
            
                print(decoded) # prints decoded instructions
                
                if inst == 0x00100073: # EBREAK check
                    break
                
                self.pc += 4 # increment program counter

        except ValueError:
            print("Error - Unsupported instruction")

    def decodeInstruction(self, inst):
        if(inst[-2]+inst[-1] == "11"):
            if (inst[-7:-2] == "01100"): # OP instruction (R type)
                funct7 = inst[-32:-25]
                funct3 = inst[-15:-12]
                rs2, rs1, rd = self.R_format(inst)
                instName = self.functOp(funct3, funct7)

                return f"{instName.rjust(6)} x{rd}, x{rs1}, x{rs2}"

            elif ((inst[-7:-2] == "00000") or (inst[-7:-2] == "00100") \
                or (inst[-7:-2] == "11001")): # LOAD/OP-IMM/JALR (I type)
                funct3 = inst[-15:-12]
                imm, rs1, rd = self.I_format(inst)

                if(inst[-7:-2] == "00000"): # LOAD
                    instName = self.funct3Load(funct3)
                    return f"{instName.rjust(6)} x{rd}, {imm}(x{rs1})"

                elif(inst[-7:-2] == "00100"): # OP-IMM
                    instName = self.functOpImm(funct3, inst[-32:-25])
                    return f"{instName.rjust(6)} x{rd}, x{rs1}, {imm}"
                
                else: # JALR
                    instName = "jalr"
                    return f"{instName.rjust(6)} x{rd}, {imm}(x{rs1})"

            elif (inst[-7:-2] == "01000"): # STORE instruction (S type)
                funct3 = inst[-15:-12]
                instName = self.funct3Store(funct3)
                imm, rs2, rs1 = self.S_format(inst)
                return f"{instName.rjust(6)} x{rs2}, {imm}(x{rs1})"

            elif (inst[-7:-2] == "11000"): # BRANCH (B type)
                funct3 = inst[-15:-12]
                instName = self.funct3Branch(funct3)
                imm, rs2, rs1 = self.B_format(inst)
                return f"{instName.rjust(6)} x{rs1}, x{rs2}, {imm}"
            
            elif (inst[-7:-2] == "00101" or inst[-7:-2] == "01101"): # AUIPC/LUI (U type)
                imm, rd = self.U_format(inst)

                if (inst[-7:-2] == "00101"): # AUIPC
                    instName = "auipc"
                else: # LUI
                    instName = "lui"

                return f"{instName.rjust(6)} x{rd}, {imm}"
            
            elif (inst[-7:-2] == "11011"): # JAL (J type)
                imm, rd = self.J_format(inst)
                instName = "jal"
                return f"{instName.rjust(6)} x{rd}, {imm}"
            
            elif (inst[-7:-2] == "11100" and inst[-32:-20] == "000000000001"):
                return "ebreak"
         
        else:
             raise ValueError("Error - Unsupported instruction")
         
    def R_format(self, inst):
        rs2 = inst[-25:-20]
        rs1 = inst[-20:-15]
        rd = inst[-12:-7]
        
        rd = int(rd, 2)
        rs1 = int(rs1, 2)
        rs2 = int(rs2, 2)
        return rs2, rs1, rd
        
    def I_format(self, inst):
        if (inst[-15:-12] == "101"and inst[-7:-2] != "00000") or \
            (inst[-15:-12] == "001" and inst[-7:-2] != "00000"):
            imm = int(inst[-25:-20], 2)
        else:
            imm = int(inst[-32:-20],2)
        rs1 = int(inst[-20:-15],2)
        rd = int(inst[-12:-7],2)
        if (imm & 0x800):
            # if msb is 1, sign extend
            imm |= 0xFFFFF000
            imm -= 0x100000000

        return imm, rs1, rd

    def S_format(self, inst):
        imm = (int(inst[-32:-25], 2) << 5) | int(inst[-12:-7], 2)
        rs2 = inst[-25:-20]
        rs1 = inst[-20:-15]
        if imm & 0x800: # if msb is 1, sign extend
            imm |= 0xFFFFF000
            imm -= 0x100000000

        rs1 = int(rs1, 2)
        rs2 = int(rs2, 2)
        return imm, rs2, rs1

    def B_format(self, inst):
        imm = 0
        imm |= (int(inst[-32],2) << 12) | (int(inst[-8],2) << 11) | \
            (int(inst[-31:-25],2) << 5) | (int(inst[-12:-8], 2) << 1)
        rs2 = inst[-25:-20]
        rs1 = inst[-20:-15]
        if imm & 0x1000: 
            # if msb is 1, sign extend
            imm |= 0xFFFFF000
            imm -= 0x100000000

        rs1 = int(rs1, 2)
        rs2 = int(rs2, 2)
        return imm, rs2, rs1

    def U_format(self, inst):
        imm = int(inst[-32:-12],2)
        rd = inst[-12:-7]
        if imm & 0x80000: # if msb is 1, sign extend
            imm |= 0xFFF00000
            imm -= 0x100000000

        rd = int(rd, 2)
        return imm, rd

    def J_format(self, inst):
        imm = 0
        imm |= (int(inst[-32],2) << 20) | (int(inst[-20:-12],2) << 12) | (int(inst[-21],2) << 11) | (int(inst[-31:-21],2) << 1)
        rd = inst[-12:-7]
        if imm & 0x100000: # if msb is 1, sign extend
            imm |= 0xFFF00000
            imm -= 0x100000000
        
        rd = int(rd, 2)
        return imm, rd

    def funct3Load(self, funct3):
        if(funct3 == "000"):
            return "lb"
        elif(funct3 == "001"):
            return "lh"
        elif(funct3 == "010"):
            return "lw"
        elif(funct3 == "100"):
            return "lbu"
        elif(funct3 == "101"):
            return "lhu"
        else:
            raise ValueError("Error - Unsupported instruction")
        
    def functOpImm(self, funct3, funct7):
        if(funct3 == "000"):
            return "addi"
        elif(funct3 == "010"):
            return "slti"
        elif(funct3 == "011"):
            return "sltiu"
        elif(funct3 == "100"):
            return "xori"
        elif(funct3 == "110"):
            return "ori"
        elif(funct3 == "111"):
            return "andi"
        elif(funct3 == "001" and funct7 == "0000000"):
            return "slli"
        elif(funct3 == "101" and funct7 == "0000000"):
            return "srli"
        elif(funct3 == "101" and funct7 == "0100000"):
            return "srai"
        else:
            raise ValueError("Error - Unsupported instruction")
        
    def funct3Store(self, funct3):
        if(funct3 == "000"):
            return "sb"
        elif(funct3 == "001"):
            return "sh"
        elif(funct3 == "010"):
            return "sw"
        else:
            raise ValueError("Error - Unsupported instruction")
        
    def funct3Branch(self, funct3):
        if(funct3 == "000"):
            return "beq"
        elif(funct3 == "001"):
            return "bne"
        elif(funct3 == "100"):
            return "blt"
        elif(funct3 == "101"):
            return "bge"
        elif(funct3 == "110"):
            return "bltu"
        elif(funct3 == "111"):
            return "bgeu"
        else:
            raise ValueError("Error - Unsupported instruction")
        
    def functOp(self, funct3, funct7):
        if(funct7 == "0000000" or funct7 == "0100000"):
            if(funct3 == "000" and funct7 == "0000000"):
                return "add"
            elif(funct3 == "000" and funct7 == "0100000"):
                return "sub"
            elif(funct3 == "001"):
                return "sll"
            elif(funct3 == "010"):
                return "slt"
            elif(funct3 == "011"):
                return "sltu"
            elif(funct3 == "100"):
                return "xor"
            elif(funct3 == "101" and funct7 == "0000000"):
                return "srl"
            elif(funct3 == "101" and funct7 == "0100000"):
                return "sra"
            elif(funct3 == "110"):
                return "or"
            elif(funct3 == "111"):
                return "and"
            else:
                raise ValueError("Error - Unsupported instruction")
            
        elif(funct7 == "0000001"):
            if(funct3 == "000"):
                return "mul"
            elif(funct3 == "001"):
                return "mulh"
            elif(funct3 == "010"):
                return "mulhsu"
            elif(funct3 == "011"):
                return "mulhu"
            elif(funct3 == "100"):
                return "div"
            elif(funct3 == "101"):
                return "divu"
            elif(funct3 == "110"):
                return "rem"
            elif(funct3 == "111"):
                return "remu"
            else:
                raise ValueError("Error - Unsupported instruction")
        
        else:
            raise ValueError("Error - Unsupported instruction")

    def getInstandReg(self, decoded, inst):
        decoded = decoded.replace("(", ", ")
        decoded = decoded.replace(")", "")
        parts = decoded.split() # pulls rd, rs1, & rs2_imm from decoded inst
        INST = parts[0].upper()
        rd = rs1 = rs2_imm = ""

        if len(parts) >= 4:
            # OP
            if (inst[-7:-2] == "01100"):
                rd_s = parts[1]
                rd = (bin(int(rd_s[1:].rstrip(","), 10))[2:]).zfill(5)
                rs1_s = parts[2]
                rs1 = (bin(int(rs1_s[1:].rstrip(","), 10))[2:]).zfill(5)
                rs2_imm_s = parts[3]
                rs2_imm = (bin(int(rs2_imm_s[1:].rstrip(","), 10))[2:]).zfill(5)
                return f"{INST.rjust(6)} {rd} {rs1} {rs2_imm}"
            
            # OPIMM
            elif(inst[-7:-2] == "00100"):
                rd_s = parts[1]
                rd = (bin(int(rd_s[1:].rstrip(","), 10))[2:]).zfill(5)
                rs1_s = parts[2]
                rs1 = (bin(int(rs1_s[1:].rstrip(","), 10))[2:]).zfill(5)
                imm_s = parts[3]
                if (INST == "SLLI" or INST == "SRLI" or INST == "SRAI"):
                    if (int(imm_s.rstrip(","), 10)) < 0 or \
                        (int(imm_s.rstrip(","), 10)) > 31:
                        raise ValueError("Error - Invalid Shift Amount (0-32)")
                    else:
                        imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(5)

                else:
                    if (int(imm_s.rstrip(","), 10)) < 0: # checking for negative value
                        imm = bin(((int(imm_s.rstrip(","), 10)) & 0xFFFFFFFF))[22:34]
                    else:
                        imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(12)
                return f"{INST.rjust(6)} {rd} {rs1} {imm}"
                
            # STORE 
            elif (inst[-7:-2] == "01000"):
                rs2_s = parts[1]
                rs2 = (bin(int(rs2_s[1:].rstrip(","), 10))[2:]).zfill(5)
                imm_s = parts[2]
                if (int(imm_s.rstrip(","), 10)) < 0: # checking for negative value
                    imm = bin(((int(imm_s.rstrip(","), 10)) & 0xFFFFFFFF))[22:34]
                else:
                    imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(12)
                rs1_s = parts[3]
                rs1 = bin(int(rs1_s[1:]))[2:].zfill(5)
                return f"{INST.rjust(6)} {rd}      {rs1} {rs2} {imm}"
                
            # LOAD / JALR
            elif ((inst[-7:-2] == "00000") or (inst[-7:-2] == "11001")):
                rd_s = parts[1]
                rd = (bin(int(rd_s[1:].rstrip(","), 10))[2:]).zfill(5)
                imm_s = parts[2]
                if (int(imm_s.rstrip(","), 10)) < 0: # checking for negative value
                    imm = bin(((int(imm_s.rstrip(","), 10)) & 0xFFFFFFFF))[22:34]
                else:
                    imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(12)
                rs1_s = parts[3]
                rs1 = bin(int(rs1_s[1:]))[2:].zfill(5)
                return f"{INST.rjust(6)} {rd} {rs1} {imm}"
            
            # BRANCH
            elif (inst[-7:-2] == "11000"):
                rs1_s = parts[1]
                rs1 = (bin(int(rs1_s[1:].rstrip(","), 10))[2:]).zfill(5)
                rs2_s = parts[2]
                rs2 = (bin(int(rs2_s[1:].rstrip(","), 10))[2:]).zfill(5)
                imm_s = parts[3]
                if (int(imm_s.rstrip(","), 10)) < 0: # checking for negative value
                    imm = bin(((int(imm_s.rstrip(","), 10)) & 0xFFFFFFFF))[21:34]
                else:
                    imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(13)
                return f"{INST.rjust(6)}       {rs1} {rs2} {imm}"
                
        elif len(parts) == 3:
            # LUI / AUIPC / JAL
            if (inst[-7:-2] == "01101" or inst[-7:-2] == "00101" or \
                  inst[-7:-2] == "11011"):
                rd_s = parts[1]
                rd = (bin(int(rd_s[1:].rstrip(","), 10))[2:]).zfill(5)
                imm_s = parts[2]

                if inst[-7:-2] == "11011": # JAL is unique, 21 bits in imm
                    if (int(imm_s.rstrip(","), 10)) < 0: # checking for negative value
                        imm = bin(((int(imm_s.rstrip(","), 10)) & 0xFFFFFFFF))[13:34]
                    else:
                        imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(21)
                else:
                    if (int(imm_s.rstrip(","), 10)) < 0: # checking for negative value
                        imm = bin(((int(imm_s.rstrip(","), 10)) & 0xFFFFFFFF))[14:34]
                    else:
                        imm = (bin(int(imm_s.rstrip(","), 10))[2:]).zfill(20)
                return f"{INST.rjust(6)} {rd}       {imm}"
                
        elif len(parts) == 1:
            return "EBREAK"
        
        else:
            raise ValueError("Error - Unsupported Instruction")
        
    def runInstruction(self, decoded2, inst):
        if (inst[-7:-2] == "01100"):
            self.runROp(decoded2)
        elif(inst[-7:-2] == "00000"):
            self.runLoadOp(decoded2)
        elif((inst[-7:-2] == "00100") or (inst[-7:-2] == "11001")):
            self.runIOp(decoded2)
        elif(inst[-7:-2] == "01000"):
            self.runSOp(decoded2)
        elif(inst[-7:-2] == "11000"):
            self.runBOp(decoded2)
        elif(inst[-7:-2] == "11011"):
            self.runJOp(decoded2)
        elif(inst[-7:-2] == "01101" or inst[-7:-2] == "00101"):
            self.runUOp(decoded2)
        self.registers[0] = 0

    def runROp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RD = int(parts[1].upper(), 2)
        RS1 = int(parts[2].upper(), 2)
        RS2 = int(parts[3].upper(), 2)
        if(INST == "ADD"):
            self.registers[RD] = self.registers[RS1] + self.registers[RS2]
            if(self.registers[RD] > 0xFFFFFFFF):
                raise ValueError("Overflow detected")
        elif(INST == "SUB"):
            self.registers[RD] = self.registers[RS1] - self.registers[RS2]
        elif(INST == "SLL"):
            self.registers[RD] = self.registers[RS1] << self.registers[RS2]
        elif(INST == "SLT"):
            if (self.registers[RS1] & 0x80000000):
                self.registers[RS1] -= 0x100000000
            if(self.registers[RS2] & 0x80000000):
                self.registers[RS2] -= 0x100000000
            if(self.registers[RS1] < self.registers[RS2]):
                self.registers[RD] = 1
            else:
                self.registers[RD] = 0
        elif(INST == "SLTU"):
            if(self.registers[RS1] > self.registers[RS2]):
                self.registers[RD] = 1
            else:
                self.registers[RD] = 0
        elif(INST == "XOR"):
            self.registers[RD] = self.registers[RS1] ^ self.registers[RS2]
        elif(INST == "SRL"):
            self.registers[RD] = (self.registers[RS1] & 0xFFFFFFFF) >> self.registers[RS2]
        elif(INST == "SRA"):
            self.registers[RD] = (self.registers[RS1] >> self.registers[RS2]) | (0xFFFFFFFF << (32 - self.registers[RS2]))
        elif(INST == "OR"):
            self.registers[RD] = self.registers[RS1] | self.registers[RS2]
        elif(INST == "AND"):
            self.registers[RD] = self.registers[RS1] & self.registers[RS2]
        elif(INST == "MUL"):
            self.registers[RD] = self.registers[RS1] * self.registers[RS2]
            if(self.registers[RD] > 0xFFFFFFFF):
                raise ValueError("Overflow detected")
        elif(INST == "MULH"):
            self.registers[RD] = ((self.registers[RS1] * self.registers[RS2]) \
                        // 0x100000000) & 0xFFFFFFFF
        elif(INST == "MULHSU"):
            self.registers[RD] = ((self.registers[RS1] * self.registers[RS2]) >> 32) & 0xFFFFFFFF
            if(self.registers[RD] > 0xFFFFFFFF):
                raise ValueError("Overflow detected")
        elif(INST == "MULHU"):
            self.registers[RD] = ((self.registers[RS1] * self.registers[RS2]) >> 32) & 0xFFFFFFFF
        elif(INST == "DIV"):
            if self.registers[RS2] == 0:
                raise ValueError("Error - Division by zero")
            self.registers[RD] = self.registers[RS1] // self.registers[RS2]
        elif(INST == "DIVU"):
            if self.registers[RS2] == 0:
                raise ValueError("Error - Division by zero")
            self.registers[RD] = (self.registers[RS1] & 0xFFFFFFFF) // (self.registers[RS2] & 0xFFFFFFFF)
        elif(INST == "REM"):
            if self.registers[RS2] == 0:
                raise ValueError("Error - Division by zero")
            self.registers[RD] = self.registers[RS1] % self.registers[RS2]
        elif(INST == "REMU"):
            if self.registers[RS2] == 0:
                raise ValueError("Error - Division by zero")
            self.registers[RD] = (self.registers[RS1] & 0xFFFFFFFF) % (self.registers[RS2] & 0xFFFFFFFF)

    def runIOp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RD = int(parts[1].upper(), 2)
        RS1 = int(parts[2].upper(), 2)
        IMM = int(parts[3].upper(), 2)
        if (IMM & 0x800):
            # if msb is 1, sign extend
            IMM |= 0xFFFFF000
            IMM -= 0x100000000
        if(INST == "ADDI"):
            self.registers[RD] = self.registers[RS1] + IMM
            if(self.registers[RD] > 0xFFFFFFFF):
                raise ValueError("Overflow detected")
        elif(INST == "SLTI"):
            self.registers[RS1] = self.registers[RS1] & 0xFFFFFFFF
            if (self.registers[RS1] & 0x80000000):
                tempReg = self.registers[RS1]
                tempReg -= 0x100000000
            else:
                tempReg = self.registers[RS1]
            if tempReg < IMM:
                self.registers[RD] = 1
            else:
                self.registers[RD] = 0
        elif(INST == "SLTIU"):
            if self.registers[RS1] < (IMM & 0xFFFFFFFF):
                self.registers[RD] = 1
            else:
                self.registers[RD] = 0
        elif(INST == "XORI"):
            self.registers[RD] = self.registers[RS1] ^ IMM
        elif(INST == "ORI"):
            self.registers[RD] = self.registers[RS1] | IMM
        elif(INST == "ANDI"):
            self.registers[RD] = self.registers[RS1] & IMM
        elif(INST == "SLLI"):
            shamt = IMM & 0b11111
            self.registers[RD] = self.registers[RS1] << shamt
        elif(INST == "SRLI"):
            shamt = IMM & 0b11111
            self.registers[RD] = (self.registers[RS1] & 0xFFFFFFFF) >> shamt
        elif(INST == "SRAI"):
            shamt = IMM & 0b11111
            if (self.registers[RS1] & 0x80000000):  # if RS1 is negative
                self.registers[RD] = (self.registers[RS1] >> shamt) | (0xFFFFFFFF << (32 - shamt))
            else:
                self.registers[RD] = self.registers[RS1] >> shamt
        elif(INST == "JALR"):
            self.registers[RD] = self.pc + 4
            targetAdr = (self.registers[RS1] + IMM) & 0xFFFFFFFE
            self.pc = targetAdr
        
    def runLoadOp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RD = int(parts[1].upper(), 2)
        RS1 = int(parts[2].upper(), 2)
        IMM = int(parts[3].upper(), 2)
        if(INST == "LB"):
            adr = self.registers[RS1] + IMM
            byteVal = self.memory[adr]
            if((byteVal & 0x80) != 0):
                byteVal = byteVal | 0xFFFFFF00
            self.registers[RD] = byteVal
        elif(INST == "LH"):
            adr = self.registers[RS1] + IMM
            hwVal = (self.memory[adr] | (self.memory[adr + 1] << 8))
            if((hwVal & 0x8000) != 0):
                hwVal = hwVal | 0xFFFF0000
            self.registers[RD] = hwVal 
        elif(INST == "LW"):
            adr = self.registers[RS1] + IMM
            wordVal = self.memory[adr] | (self.memory[adr + 1] << 8) \
                 | (self.memory[adr + 2] << 16) | (self.memory[adr + 3] << 24)
            self.registers[RD] = wordVal
        elif(INST == "LBU"):
            adr = self.registers[RS1] + IMM
            byteVal = self.memory[adr]
            self.registers[RD] = byteVal
        elif(INST == "LHU"):
            adr = self.registers[RS1] + IMM
            hwVal = (self.memory[adr] | (self.memory[adr + 1] << 8))
            self.registers[RD] = hwVal

    def runSOp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RS1 = int(parts[1].upper(), 2)
        RS2 = int(parts[2].upper(), 2)
        IMM = int(parts[3].upper(), 2)
        if (IMM & 0x800): # if msb is 1, sign extend
            IMM |= 0xFFFFF000
            IMM -= 0x100000000
        if(INST == "SB"):
            adr = self.registers[RS1] + IMM
            if ((adr > 0xFFFFF) or (adr < 0x0)):
                print("Address", adr, "does not exist in memory")
                self.exitMonitor()
            data = self.registers[RS2] & 0xFF
            self.memory[adr] = data
        elif(INST == "SH"):
            adr = self.registers[RS1] + IMM
            if ((adr > 0xFFFFF) or (adr < 0x0)):
                print("Address", adr, "does not exist in memory")
                self.exitMonitor()
            data = self.registers[RS2] & 0xFFFF
            self.memory[adr] = data & 0xFF
            self.memory[adr + 1] = (data >> 8) & 0xFF
        elif(INST == "SW"):
            adr = self.registers[RS1] + IMM
            if ((adr > 0xFFFFF) or (adr < 0x0)):
                print("Address", adr, "does not exist in memory")
                self.exitMonitor()
            data = self.registers[RS2] & 0xFFFFFFFF
            self.memory[adr] = data & 0xFF
            self.memory[adr + 1] = (data >> 8) & 0xFF
            self.memory[adr + 2] = (data >> 16) & 0xFF
            self.memory[adr + 3] = (data >> 24) & 0xFF

    def runBOp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RS1 = int(parts[1].upper(), 2)
        RS2 = int(parts[2].upper(), 2)
        IMM = int(parts[3].upper(), 2)
        if (IMM & 0x1000):
            IMM |= 0xFFFFF000
            IMM -= 0x100000000
        if(INST == "BEQ"):
            if (self.registers[RS1] == self.registers[RS2]):
                targetAdr = self.pc + IMM
                self.pc = targetAdr
            else:
                self.pc += 4

        elif(INST == "BNE"):
            if (self.registers[RS1] != self.registers[RS2]):
                targetAdr = self.pc + IMM
                self.pc = targetAdr
            else:
                self.pc += 4

        elif(INST == "BLT"):
            if self.registers[RS1] < self.registers[RS2]:
                targetAdr = self.pc + IMM
                self.pc = targetAdr
            else:
                self.pc += 4

        elif(INST == "BGE"):
            if self.registers[RS1] > self.registers[RS2]:
                targetAdr = self.pc + IMM
                self.pc = targetAdr
            else:
                self.pc += 4

        elif(INST == "BLTU"):
            if (self.registers[RS1] & 0xFFFFFFFF) < (self.registers[RS2] & 0xFFFFFFFF):
                targetAdr = self.pc + IMM
                self.pc = targetAdr
            else:
                self.pc += 4

        elif(INST == "BGEU"):
            if (self.registers[RS1] & 0xFFFFFFFF) > (self.registers[RS2] & 0xFFFFFFFF):
                targetAdr = self.pc + IMM
                self.pc = targetAdr
            else:
                self.pc += 4

    def runJOp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RD = int(parts[1].upper(), 2)
        IMM = int(parts[2].upper(), 2)
        if (IMM & 0x100000): # if msb is 1, sign extend
            IMM |= 0xFFF00000
            IMM -= 0x100000000
        if(INST == "JAL"):
            self.registers[RD] = self.pc + 4
            targetAdr = (self.pc + IMM) & 0xFFFFFFFE
            self.pc = targetAdr

    def runUOp(self, decoded2):
        parts = decoded2.split() # pulls name, rd, rs1, & rs2 from runProgram
        INST = parts[0].upper()
        RD = int(parts[1].upper(), 2)
        IMM = int(parts[2].upper(), 2)
        if (IMM & 0x100000): # if msb is 1, sign extend
            IMM |= 0xFFF00000
            IMM -= 0x100000000
        if(INST == "LUI"):
            upperImm = IMM << 12
            self.registers[RD] = upperImm
            self.pc += 4
        elif(INST == "AUIPC"):
            upperImm = IMM << 12
            self.registers[RD] = self.pc + upperImm

    def startMonitor(self):
        self.monitorRunning = True

        try:
            i=0
            while self.monitorRunning:
                cmd = input("> ")
                self.commandList(cmd, i)
                if(cmd.endswith("s") and cmd != "s" or cmd == "info"):
                    i = i+1
                else:
                    i=0

        except KeyboardInterrupt: # Ctrl-C (keyboard interrupt)
            print("KeyboardInterrupt")
            self.exitMonitor()

        except EOFError: # EOF is Ctrl-Z+Enter on Windows instead of Ctrl-D
            self.exitMonitor()

    def commandList(self, cmd, i):

        if cmd.find(".") != -1:
            x = cmd.split(".")

            startAdrStr = x[0]
            endAdrStr = x[1]

            self.displayMemoryRange(startAdrStr, endAdrStr)

        elif cmd.find(":") != -1:
            self.editMemory(cmd)

        elif cmd.endswith("r") and cmd != "r":
            startAdrStr = cmd.rstrip("r")
            self.runProgram(startAdrStr)

        elif cmd.endswith("s") and cmd != "s":
            if(i==0):
                self.pc = cmd.rstrip("s")
                self.registers = [0]*32 # x0-x31 registers
                self.registers[2] = 0x000FFFFF
                self.pc = int(self.pc, 16)
            self.runProgramStep()

        elif (cmd.endswith("t") and cmd != "exit") and cmd != "t":
            startAdrStr = cmd.rstrip("t")
            self.disassembleCode(startAdrStr)

        elif cmd == "info":
            self.displayInfo()
        
        elif cmd == "exit":
            self.exitMonitor()

        elif not((cmd.find(".") != -1) or (cmd.find(":") != -1) or (cmd.find("r") != -1)):
            self.displayMemory(cmd)

        else:
            print("Unknown command:", cmd)

    def displayInfo(self):
        i = 0
        while( i < 32 ):
            regValue = hex(self.registers[i] & 0xFFFFFFFF)
            if(i < 10):
                print(f" x{i}", regValue.replace("0x", "").zfill(8).upper())
            else:
                print(f"x{i}", regValue.replace("0x", "").zfill(8).upper())
            i = i + 1

    def exitMonitor(self):
        print(">>>")
        self.memory = bytearray(1048756) * 0
        self.zero = [0]                  
        self.registers = [0]*31
        self.pc = 0
        self.monitorRunning = False
        exit(1)

##########################################################################################
#                                         MAIN                                           #
##########################################################################################

def main():
    emulator = YB60() # creates an instance of the emulator

    if len(sys.argv) > 1:
        fileName = sys.argv[1] # if additional command is provided, attempt opening a file

        emulator.__init__() # initialize the monitor
        emulator.loadProgram(fileName) # load program from fileName

    else: # start program, no file
        emulator.__init__()
        emulator.startMonitor()

if __name__ == "__main__":
    main()