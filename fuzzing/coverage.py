from os import chdir,listdir,environ
from os.path import isfile,join
from subprocess import DEVNULL, run
import sys

ignored_files = "-ignore-filename-regex=glib -ignore-filename-regex=fuzz -ignore-filename-regex=helper -ignore-filename-regex=h$"

if __name__ == "__main__":
    chdir("build/fuzzing/out")
    available_targets = [exe for exe in listdir("../") if isfile(join("..", exe))]
    if len(sys.argv) != 3 :
        print("usage : python coverage.py fuzz_target result_type")
        print("available targets : ")
        print(available_targets)
        print("available result types : \n export \n show \n report (default)")
        exit(0)
    fuzzing_target = sys.argv[1]
    result_type = sys.argv[2]
    if fuzzing_target in available_targets:
        environ["LLVM_PROFILE_FILE"] = fuzzing_target + "_%p.profraw"
        corpus_path = "../../../fuzzing/IN/"
        corpus = listdir(corpus_path)
        for f in corpus:
            #print(corpus_path+f)
            run(["../" + fuzzing_target, corpus_path+f,"-detect_leaks=0"], stdin=DEVNULL, stdout=DEVNULL, stderr=DEVNULL)
        run(["llvm-profdata merge -sparse " + fuzzing_target + "_*.profraw -o " + fuzzing_target + ".profdata"], shell=True)
        if result_type == "export" :
            run(["llvm-cov show ../" + fuzzing_target + " -format=html -output-dir=../report -instr-profile=" + fuzzing_target + ".profdata " + ignored_files], shell=True)
        elif result_type == "show" :
            run(["llvm-cov show ../" + fuzzing_target + " -instr-profile=" + fuzzing_target + ".profdata " + ignored_files], shell=True)
        else:
            run(["llvm-cov report ../" + fuzzing_target + " -instr-profile=" + fuzzing_target + ".profdata " + ignored_files], shell=True)
