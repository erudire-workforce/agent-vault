// Final-review item 5: no non-test code may seal a value without AAD. The
// scan parses every non-test Go file in the module and reports
//   - any call to crypto.Encrypt (the nil-AAD legacy seal), and
//   - any crypto.EncryptAAD call whose AAD argument is nil, an empty
//     []byte literal, []byte(nil) or "".
// It is shown to catch planted cases before its silence on the tree counts.
// Run with: go test -tags finalfix ./internal/crypto/
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

// nilAADCalls returns "file:line: call" for every offending call in src.
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
	ast.Inspect(f, func(n ast.Node) bool {
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
		}
		return true
	})
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
