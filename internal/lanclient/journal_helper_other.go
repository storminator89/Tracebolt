//go:build !linux

package lanclient

import (
	"context"
	"localrmm/internal/journalhelper"
)

func callJournalHelper(context.Context, journalLocal, journalhelper.Request) (journalhelper.Response, error) {
	return journalhelper.Response{}, errJournalHelper
}
