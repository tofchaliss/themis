// Command deliveryctl is the operator's surface over outward-delivery intents (N-M1a,
// EDR-DELIVERY-01 Revision 3):
//
//	deliveryctl list-deadletters [--limit 50] [--since 168h]
//	deliveryctl retry  --id <intent-id>
//	deliveryctl cancel --id <intent-id>
//
// A delivery that gives up must be VISIBLE and ACTIONABLE to a person — that is the whole
// reason dead-lettering is allowed to be a terminal state. It is a CLI and not an HTTP route
// on purpose: N-M1a adds no API surface, and these are administrative acts on a node's own
// database, like `authadmin`.
//
// `retry` resets a dead-lettered intent to pending (attempts 0, error cleared, due now) so the
// worker picks it up again; `cancel` abandons it. Neither touches a Finding or a Position:
// an outward delivery is a projection, and abandoning one changes no security truth
// (EDR-DELIVERY-01 RC-7). A DELIVERED intent can be neither retried nor cancelled — the mail
// has gone.
//
// Reads THEMIS_DATABASE_DSN, the Communication node's own database.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
)

// intentOps is the slice of the delivery-intent store this CLI needs. Declaring it here keeps
// the commands testable without a database — the store satisfies it.
type intentOps interface {
	ListDeadLetters(ctx context.Context, since time.Time, limit int) ([]app.Intent, error)
	RetryIntent(ctx context.Context, id string) error
	CancelIntent(ctx context.Context, id string) error
}

// opener yields the ops seam and a cleanup; swapped in tests.
type opener func() (intentOps, func(), error)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	os.Exit(run(os.Args[1], os.Args[2:], os.Stdout, os.Stderr, openStore))
}

func run(cmd string, args []string, out, errOut io.Writer, open opener) int {
	switch cmd {
	case "list-deadletters":
		return listDeadLetters(args, out, errOut, open)
	case "retry":
		return mutate("retry", args, out, errOut, open)
	case "cancel":
		return mutate("cancel", args, out, errOut, open)
	default:
		usage(errOut)
		return 2
	}
}

// pf / pln are the CLI's print helpers. The output is informational, a failed write to the
// terminal is not something the command can act on, and discarding that error in ONE place
// keeps every call site readable.
func pf(w io.Writer, format string, args ...any) { _, _ = fmt.Fprintf(w, format, args...) }

func pln(w io.Writer, args ...any) { _, _ = fmt.Fprintln(w, args...) }

func usage(w io.Writer) {
	pln(w, "usage:")
	pln(w, "  deliveryctl list-deadletters [--limit 50] [--since 168h]")
	pln(w, "  deliveryctl retry  --id <intent-id>")
	pln(w, "  deliveryctl cancel --id <intent-id>")
	pln(w, "\nlist-deadletters  deliveries that gave up, newest first")
	pln(w, "retry             reset one to pending (attempts 0, error cleared, due now)")
	pln(w, "cancel            abandon one; changes no Finding and no Position")
	pln(w, "\nreads THEMIS_DATABASE_DSN (the Communication database)")
}

func listDeadLetters(args []string, out, errOut io.Writer, open opener) int {
	fs := flag.NewFlagSet("list-deadletters", flag.ContinueOnError)
	fs.SetOutput(errOut)
	limit := fs.Int("limit", 50, "maximum rows to print")
	since := fs.Duration("since", 7*24*time.Hour, "only intents updated within this window")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *limit <= 0 {
		pln(errOut, "list-deadletters: --limit must be positive")
		return 2
	}

	ops, closeOps, err := open()
	if err != nil {
		pln(errOut, "list-deadletters:", err)
		return 1
	}
	defer closeOps()

	intents, err := ops.ListDeadLetters(context.Background(), time.Now().UTC().Add(-*since), *limit)
	if err != nil {
		pln(errOut, "list-deadletters:", err)
		return 1
	}
	if len(intents) == 0 {
		pln(out, "no dead-lettered delivery intents")
		return 0
	}
	pf(out, "%-38s %-11s %-24s %-8s %s\n", "INTENT", "TYPE", "DESTINATION", "ATTEMPTS", "LAST ERROR")
	for _, in := range intents {
		pf(out, "%-38s %-11s %-24s %-8d %s\n", in.ID, in.Type, in.Destination, in.Attempts, in.LastError)
	}
	return 0
}

// mutate runs retry or cancel — the two commands differ only in the store call and the word
// printed, so they share the flag handling and the exit codes.
func mutate(name string, args []string, out, errOut io.Writer, open opener) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(errOut)
	id := fs.String("id", "", "delivery intent id (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" {
		pf(errOut, "%s: --id is required\n", name)
		return 2
	}

	ops, closeOps, err := open()
	if err != nil {
		pf(errOut, "%s: %v\n", name, err)
		return 1
	}
	defer closeOps()

	ctx := context.Background()
	done := "cancelled"
	if name == "retry" {
		done = "reset to pending"
		err = ops.RetryIntent(ctx, *id)
	} else {
		err = ops.CancelIntent(ctx, *id)
	}
	switch {
	case errors.Is(err, app.ErrIntentNotFound):
		// Unknown id, or an intent already delivered — either way nothing changed, and an
		// operator must not read that as success.
		pf(errOut, "%s: no actionable delivery intent %q (unknown, or already delivered)\n", name, *id)
		return 1
	case err != nil:
		pf(errOut, "%s: %v\n", name, err)
		return 1
	}
	pf(out, "delivery intent %s: %s\n", *id, done)
	return 0
}

func openStore() (intentOps, func(), error) {
	dsn := os.Getenv("THEMIS_DATABASE_DSN")
	if dsn == "" {
		return nil, nil, errors.New("THEMIS_DATABASE_DSN is required")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return nil, nil, err
	}
	return store.New(pool), pool.Close, nil
}
