package permio

import (
	"context"
	"iter"

	paginationv1 "github.com/PrivateJAR/permio-go/proto/pagination/v1"
	"google.golang.org/protobuf/proto"
)

// MaxPageSize is the largest page the API accepts (PaginationRequest.limit is 1..100).
const MaxPageSize = 100

// MaxBatch is the most resources or permissions one Check or BatchCheck call
// accepts, and the most principals [Groups.AddMembers] and
// [Groups.RemoveMembers] accept.
const MaxBatch = 100

// ListOptions configures a paginated listing.
type ListOptions struct {
	// Search filters by name, where the listing supports it.
	Search string
	// PageSize is the number of items per request, 1..100. Default 100.
	PageSize int
}

func (o *ListOptions) search() string {
	if o == nil {
		return ""
	}
	return o.Search
}

func (o *ListOptions) pageSize() int32 {
	if o == nil || o.PageSize <= 0 || o.PageSize > MaxPageSize {
		return MaxPageSize
	}
	return int32(o.PageSize)
}

// paginate iterates every item of a list RPC, following next_cursor until the
// API returns an empty one. A failing page yields the error once and ends the
// iteration. A cursor the API already returned would loop forever, so it
// yields an error rather than ending quietly with a partial listing.
func paginate[T any](ctx context.Context, pageSize int32, fetch func(ctx context.Context, p *paginationv1.PaginationRequest) ([]T, string, error)) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		var cursor *string
		seen := map[string]bool{}
		for {
			if err := ctx.Err(); err != nil {
				yield(zero, toError(err, nil))
				return
			}
			items, next, err := fetch(ctx, &paginationv1.PaginationRequest{Limit: proto.Int32(pageSize), Cursor: cursor})
			if err != nil {
				yield(zero, err)
				return
			}
			for _, it := range items {
				if !yield(it, nil) {
					return
				}
			}
			if next == "" {
				return
			}
			if seen[next] {
				yield(zero, inconsistent("the pagination cursor %q was returned twice; the listing is incomplete", next))
				return
			}
			seen[next] = true
			cursor = proto.String(next)
		}
	}
}

// failed is an iterator that yields one error.
func failed[T any](err error) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		var zero T
		yield(zero, err)
	}
}

// Collect gathers every item of a listing into a slice, stopping at the first
// error:
//
//	roles, err := permio.Collect(client.ListRoles(ctx, nil))
func Collect[T any](seq iter.Seq2[T, error]) ([]T, error) {
	out := []T{}
	for v, err := range seq {
		if err != nil {
			return out, err
		}
		out = append(out, v)
	}
	return out, nil
}
