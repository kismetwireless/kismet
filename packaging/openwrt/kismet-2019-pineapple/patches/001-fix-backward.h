--- a/backward.h
+++ b/backward.h
@@ -2051,11 +2051,11 @@ private:
 		Printer printer;
 		printer.address = true;
 		printer.print(st, stderr);
-
+/*
 #if _XOPEN_SOURCE >= 700 || _POSIX_C_SOURCE >= 200809L
 		psiginfo(info, 0);
 #endif
-
+*/
 		// try to forward the signal.
 		raise(info->si_signo);
 
