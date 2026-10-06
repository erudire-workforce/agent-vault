// Final-review item 5: no non-test code may seal or open a value without
// AAD. The scan parses every non-test Go file in the module and reports
//   - any call to crypto.Encrypt (the nil-AAD legacy seal),
//   - any crypto.EncryptAAD or crypto.DecryptAAD call whose AAD argument is
//     nil, an empty []byte literal, []byte(nil) or "", and
//   - any call to crypto.Decrypt (the nil-AAD legacy open) outside the
//     legacy-migration allowlist below.
//
// It is shown to catch planted cases before its silence on the tree counts.
package crypto

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const cryptoImportPath = "github.com/Infisical/agent-vault/internal/crypto"

// legacyDecryptAllowlist names the only places that may open a nil-AAD
// (v0.40.0) ciphertext: the one-time migration and the legacy-upgrade
// helpers. Keys are slash paths relative to the module root; "*" allows
// every function in the file's directory.
var legacyDecryptAllowlist = map[string]map[string]bool{
	"internal/aadmigrate/":  {"*": true},
	"internal/auth/auth.go": {"UnlockLegacy": true, "verifyLegacySentinel": true},
	"internal/ca/soft.go":   {"RewrapLegacyRootKey": true},
}

func legacyDecryptAllowed(filename, fn string) bool {
	p := filepath.ToSlash(filename)
	for strings.HasPrefix(p, "../") {
		p = strings.TrimPrefix(p, "../")
	}
	for prefix, fns := range legacyDecryptAllowlist {
		if strings.HasSuffix(prefix, "/") {
			if strings.HasPrefix(p, prefix) && fns["*"] {
				return true
			}
			continue
		}
		if p == prefix && fns[fn] {
			return true
		}
	}
	return false
}

// nilAADCalls returns "file:line: call" for every offending call in src.
// filename is the module-relative path used for the allowlist.
func nilAADCalls(fset *token.FileSet, filename string, src any) ([]string, error) {
	f, err := parser.ParseFile(fset, filename, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		if p != cryptoImportPath {
			continue
		}
		name := "crypto"
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name != "_" {
			aliases[name] = true
		}
	}
	if len(aliases) == 0 {
		return nil, nil
	}
	var out []string
	inspect := func(fn string, root ast.Node) {
		ast.Inspect(root, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok || !aliases[x.Name] {
				return true
			}
			pos := fset.Position(call.Pos())
			switch sel.Sel.Name {
			case "Encrypt":
				out = append(out, pos.String()+": "+x.Name+".Encrypt (no AAD)")
			case "EncryptAAD":
				if len(call.Args) == 3 && emptyAAD(call.Args[2]) {
					out = append(out, pos.String()+": "+x.Name+".EncryptAAD with empty AAD")
				}
			case "DecryptAAD":
				if len(call.Args) == 4 && emptyAAD(call.Args[3]) {
					out = append(out, pos.String()+": "+x.Name+".DecryptAAD with empty AAD")
				}
			case "Decrypt":
				if !legacyDecryptAllowed(filename, fn) {
					out = append(out, pos.String()+": "+x.Name+".Decrypt (no AAD) in "+fn+", outside the legacy-migration allowlist")
				}
			}
			return true
		})
	}
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			inspect(fd.Name.Name, fd)
			continue
		}
		inspect("", d) // package-level vars and init expressions
	}
	return out, nil
}

func emptyAAD(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == "nil"
	case *ast.BasicLit:
		return v.Kind == token.STRING && (v.Value == `""` || v.Value == "``")
	case *ast.CompositeLit: // []byte{}
		return len(v.Elts) == 0
	case *ast.CallExpr: // []byte(nil), []byte("")
		if len(v.Args) == 1 {
			return emptyAAD(v.Args[0])
		}
	}
	return false
}

func TestFinalFix_NilAADScanCatchesPlantedCases(t *testing.T) {
	planted := `package x
import (
	"github.com/Infisical/agent-vault/internal/crypto"
	vc "github.com/Infisical/agent-vault/internal/crypto"
)
func f(k, a []byte) {
	crypto.Encrypt([]byte("v"), k)
	vc.Encrypt([]byte("v"), k)
	crypto.EncryptAAD([]byte("v"), k, nil)
	crypto.EncryptAAD([]byte("v"), k, []byte{})
	crypto.EncryptAAD([]byte("v"), k, []byte(nil))
	crypto.EncryptAAD([]byte("v"), k, a) // fine
}`
	got, err := nilAADCalls(token.NewFileSet(), "planted.go", planted)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("scanner found %d of 5 planted cases: %v", len(got), got)
	}
	clean := `package x
import "github.com/Infisical/agent-vault/internal/crypto"
func f(k, a []byte) { crypto.EncryptAAD([]byte("v"), k, a) }`
	if got, _ := nilAADCalls(token.NewFileSet(), "clean.go", clean); len(got) != 0 {
		t.Fatalf("scanner flagged a call with AAD: %v", got)
	}
}

// Known positive for the Decrypt rule: nil-AAD opens are flagged everywhere
// except the allowlisted legacy-migration functions, and an allowlisted
// function name in another file is still flagged.
func TestFinalFix_NilAADScanCatchesPlantedDecrypts(t *testing.T) {
	src := func(fn string) string {
		return `package x
import "github.com/Infisical/agent-vault/internal/crypto"
func ` + fn + `(c, n, k []byte) {
	crypto.Decrypt(c, n, k)
	crypto.DecryptAAD(c, n, k, nil)
}`
	}
	cases := []struct {
		file, fn string
		want     int
	}{
		{"internal/server/planted.go", "readValue", 2},          // Decrypt + DecryptAAD(nil)
		{"internal/auth/auth.go", "Unlock", 2},                  // allowlisted file, wrong function
		{"internal/server/auth.go", "UnlockLegacy", 2},          // allowlisted name, wrong file
		{"internal/auth/auth.go", "UnlockLegacy", 1},            // Decrypt allowed; DecryptAAD(nil) never
		{"internal/aadmigrate/aadmigrate.go", "rewrapRow", 1},   // same
		{"../../internal/ca/soft.go", "RewrapLegacyRootKey", 1}, // walk-relative path, same
	}
	for _, c := range cases {
		got, err := nilAADCalls(token.NewFileSet(), c.file, src(c.fn))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != c.want {
			t.Errorf("%s %s: scanner reported %d, want %d: %v", c.file, c.fn, len(got), c.want, got)
		}
	}
}

func TestFinalFix_NoNilAADSealInNonTestCode(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var hits []string
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "vendor", ".git", "web", "sdks", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		scanned++
		found, err := nilAADCalls(fset, p, nil)
		if err != nil {
			return err
		}
		hits = append(hits, found...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 50 {
		t.Fatalf("scan covered only %d files; the walk is not reaching the module", scanned)
	}
	for _, h := range hits {
		t.Errorf("value sealed without AAD in non-test code: %s", h)
	}
}
