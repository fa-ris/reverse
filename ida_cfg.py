import idaapi, idautils, idc, ida_ida, ida_bytes

class myplugin_t(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Plugin to generate DOT graph file for every function."
    help = "This is help"
    wanted_name = "CFG Plugin"
    wanted_hotkey = "Alt-P"

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        print("Creating DOT files and executing...")
        self.basic_blocks()
        print("Done!")

    def term(self):  
        pass
    
    '''
    Function to parse through basic blocks and return chain for all its instructions.
    '''
    def basic_blocks(self):
        functions = idautils.Functions()
        for function in functions:
            flowchart = idaapi.FlowChart(idaapi.get_func(function), flags=idaapi.FC_PREDS)
            fname = str(hex(function)) + ".dot"
            if fname:
                f = open(fname, "w")
                buffer = "digraph controlflow {\n"
                i = 1
                inst_dict = {}
                numb_dict = {}
                for block in flowchart:
                    if (hex(block.start_ea) == hex(block.end_ea)):
                        i_list = idc.generate_disasm_line(block.start_ea, 0).split(" ")
                        if len(i_list) > 1:
                            i_list = [i_list[0]] + i_list[5:]
                        d, u = self.get_def_use_ops(i_list)
                        buffer += "  n" + str(i) + ' [label = "' + str(hex(block.start_ea)) + '; D:' + d.rstrip(",") + ' U: ' + u.rstrip(",") + '"];\n'
                        inst_dict[str(hex(block.start_ea))] = i
                        numb_dict[str(hex(block.start_ea))] = "n" + str(i)
                        i += 1
                        continue
                    for instruction in idautils.Heads(block.start_ea, block.end_ea):
                        i_list = idc.generate_disasm_line(instruction, 0).split(" ")
                        if len(i_list) > 1:
                            i_list = [i_list[0]] + i_list[5:]
                        d, u = self.get_def_use_ops(i_list)
                        buffer += "  n" + str(i) + ' [label = "' + str(hex(instruction)) + '; D:' + d.rstrip(",") + ' U: ' + u.rstrip(",") + '"];\n'
                        inst_dict[str(hex(instruction))] = i
                        numb_dict[str(hex(instruction))] = "n" + str(i)
                        i += 1
                buffer += "\n"
                for block in flowchart:
                    for instruction in idautils.Heads(block.start_ea, block.end_ea):
                        for i in idautils.CodeRefsFrom(instruction, 0):
                            if str(hex(instruction)) in numb_dict.keys() and str(hex(i)) in numb_dict.keys():
                                buffer += "  " + numb_dict[str(hex(instruction))] + " -> " + numb_dict[str(hex(i))] + "\n"
                        if str(hex(instruction)) in numb_dict.keys() and str(hex(ida_bytes.next_head(instruction,  ida_ida.cvar.inf.max_ea))) in numb_dict.keys():
                            buffer += "  " + numb_dict[str(hex(instruction))] + " -> " + numb_dict[str(hex(ida_bytes.next_head(instruction,  ida_ida.cvar.inf.max_ea)))] + "\n"          
                buffer += "}"
                f.write(buffer)
                f.close()

    '''
    Function to give a specific DEF/USE chain for each operator.
    '''
    def get_def_use_ops(self, i_arr):
        if i_arr[0][0] == "j":
            if i_arr[0] in ["jnz", "jne", "je", "jz"]:
                return ("", "ZF")
            elif i_arr[0] in ["jbe", "jna", "ja", "jnbe"]:
                return ("", "ZF, CF")
            elif i_arr[0] in ["jb", "jnae", "jc", "jnb", "jae", "jnc"]:
                return ("", "CF")
            elif i_arr[0] in ["jo", "jno"]:
                return ("", "OF")
            elif i_arr[0] in ["js", "jns"]:
                return ("", "SF")
            elif i_arr[0] in ["jle", "jng", "jg", "jnle"]:
                return ("", "ZF, SF, OF")
            elif i_arr[0] in ["jl", "jnge", "jge", "jnl"]:
                return ("", "SF, OF")
            else:
                return ("", "")
        elif i_arr[0] == "push":
            if len(i_arr) > 1 and len(i_arr[1]) <= 3:
                return ("[ESP], ESP", "ESP, " + i_arr[1].upper())
            else:
                return ("[ESP], ESP", "ESP")
        elif i_arr[0] == "pop":
            return (i_arr[1] + " ESP", "[ESP], ESP")
        elif i_arr[0] in ["xor", "add", "or", "sub", "and", "inc", "dec", "imul", "sar", "shr"]:
            if len(i_arr) == 2:
                return ("CF, OF, SF, ZF, " + i_arr[1].upper(), i_arr[1].upper())
            elif i_arr[2][0] not in ["e", "a", "["]:
                return ("CF, OF, SF, ZF, " + i_arr[1].upper(), i_arr[1].upper())
            else:
                return ("CF, OF, SF, ZF, " + i_arr[1].upper(), i_arr[1].upper())
        elif i_arr[0] == "lea":
            return (i_arr[1].upper(), i_arr[2][1:4].upper())
        elif i_arr[0] == "call":
            if len(i_arr) == 2 and len(i_arr[1]) > 3 and i_arr[1][0:3] == "ds:":
                return ("ESP, EAX", "ESP, [" + i_arr[1][3:].upper() + "]")
            elif len(i_arr) == 2:
                return ("ESP, EAX", "ESP, " + i_arr[1].upper())
            else:
                return ("ESP, EAX", "ESP")
        elif i_arr[0] == "test":
            return ("OF, CF, SF, ZF", i_arr[1].upper())
        elif len(i_arr[0]) >= 5 and "leave" in i_arr[0]:
            return ("ESP, EBP", "EBP")
        elif i_arr[0] == "rep":
            return ("[EDI]", "ECX")
        elif i_arr[0] == "setnz" and len(i_arr) > 1:
            return (i_arr[1].upper(), "ZF")
        elif i_arr[0] == "cmp":
            i_arr[1] = i_arr[1].strip(",")
            i_arr[2] = i_arr[2].strip(",")
            if "h" not in i_arr[2]:
                if len(i_arr[1].strip("[]")) == 3:
                    return ("OF, CF, SF, ZF, " + i_arr[1].strip("[]").upper(), i_arr[1].upper() + ", " + i_arr[2].upper())
                elif len(i_arr[2].strip("[]")) == 3:
                    return ("OF, CF, SF, ZF, " + i_arr[1].upper(), i_arr[2].strip("[]").upper())
                elif len(i_arr[1]) > 5 and len(i_arr[2]) <= 5:
                    return ("OF, CF, SF, ZF", i_arr[2].upper())
                else:
                    return ("OF, CF, SF, ZF", i_arr[1].rstrip(",").upper() + ", " + i_arr[2].rstrip(",").upper())
            else:
                if len(i_arr[1].strip("[]")) == 3:
                    return ("OF, CF, SF, ZF, " + i_arr[1].strip("[]").upper(), i_arr[1].upper())
                elif len(i_arr[2].strip("[]")) == 3:
                    return ("OF, CF, SF, ZF, " + i_arr[1].upper(), i_arr[1].upper())
                elif len(i_arr[1]) > 5 and len(i_arr[2]) <= 5:
                    return ("OF, CF, SF, ZF", i_arr[1].strip("[]").upper())
                else:
                    return ("OF, CF, SF, ZF", i_arr[1].rstrip(",").strip("[]").upper())
        elif i_arr[0] == "mov":
            if len(i_arr) > 2 and "fs" in i_arr[2]:
                return (i_arr[2].upper(), "FS_OFFSET, " + i_arr[3].upper())
            elif len(i_arr) > 3 and "fs" in i_arr[3]:
                return (i_arr[1].upper(), i_arr[3].upper() + ", FS_OFFSET")
            elif len(i_arr) > 2 and "[" in i_arr[2]:
                return (i_arr[1].upper(), i_arr[2][1:4].upper() + ", " + i_arr[2].upper())
            elif len(i_arr) > 2:
                return (i_arr[1].upper(), i_arr[2].upper())
        elif i_arr[0] == "movsx":
            return (i_arr[1].upper(), i_arr[2][1:4].upper() + ", " + i_arr[2][5:-2].upper())
        elif i_arr[0] == "movzx":
            return ("EAX", "EBP, StartupInfo.wShowWindow")
        else:
            return ("", "")

def PLUGIN_ENTRY():
    return myplugin_t()
