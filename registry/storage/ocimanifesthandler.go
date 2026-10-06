package storage

import (
	"context"
	"fmt"
	"net/url"

	"github.com/distribution/distribution/v3"
	"github.com/distribution/distribution/v3/internal/dcontext"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// ocischemaManifestHandler is a ManifestHandler that covers ocischema manifests.
type ocischemaManifestHandler struct {
	repository   distribution.Repository
	blobStore    *linkedBlobStore
	ctx          context.Context
	manifestURLs manifestURLs
	references   ReferenceService
}

var _ ManifestHandler = &ocischemaManifestHandler{}

func (ms *ocischemaManifestHandler) Unmarshal(ctx context.Context, dgst digest.Digest, content []byte) (distribution.Manifest, error) {
	dcontext.GetLogger(ms.ctx).Debug("(*ocischemaManifestHandler).Unmarshal")

	m := &ocischema.DeserializedManifest{}
	if err := m.UnmarshalJSON(content); err != nil {
		return nil, err
	}

	return m, nil
}

func (ms *ocischemaManifestHandler) Put(ctx context.Context, manifest distribution.Manifest, skipDependencyVerification bool) (digest.Digest, error) {
	dcontext.GetLogger(ms.ctx).Debug("(*ocischemaManifestHandler).Put")

	m, ok := manifest.(*ocischema.DeserializedManifest)
	if !ok {
		return "", fmt.Errorf("non-ocischema manifest put to ocischemaManifestHandler: %T", manifest)
	}

	if err := ms.verifyManifest(ms.ctx, *m, skipDependencyVerification); err != nil {
		return "", err
	}

	mt, payload, err := manifest.Payload()
	if err != nil {
		return "", err
	}

	return putManifest(ctx, ms.blobStore, ms.references, manifest, mt, payload)
}

func putManifest(ctx context.Context, blobStore *linkedBlobStore, references ReferenceService, manifest distribution.Manifest, mediaType string, payload []byte) (digest.Digest, error) {
	referrer, ok := manifest.(distribution.Referrer)
	if !ok || referrer.Subject() == nil {
		revision, err := blobStore.Put(ctx, mediaType, payload)
		if err != nil {
			dcontext.GetLogger(ctx).Errorf("error putting payload into blobstore: %v", err)
			return "", err
		}
		return revision.Digest, nil
	}

	revision, err := blobStore.put(ctx, mediaType, payload)
	if err != nil {
		dcontext.GetLogger(ctx).Errorf("error putting payload into blobstore: %v", err)
		return "", err
	}

	if err := references.Link(ctx, referrer.Type(), revision.Digest, referrer.Subject().Digest); err != nil {
		return "", err
	}
	if err := blobStore.publish(ctx, revision); err != nil {
		return "", err
	}

	return revision.Digest, nil
}

// verifyManifest ensures that the manifest content is valid from the
// perspective of the registry. As a policy, the registry only tries to store
// valid content, leaving trust policies of that content up to consumers.
func (ms *ocischemaManifestHandler) verifyManifest(ctx context.Context, mnfst ocischema.DeserializedManifest, skipDependencyVerification bool) error {
	var errs distribution.ErrManifestVerification

	if mnfst.Manifest.SchemaVersion != 2 {
		return fmt.Errorf("unrecognized manifest schema version %d", mnfst.Manifest.SchemaVersion)
	}

	if skipDependencyVerification {
		return nil
	}

	manifestService, err := ms.repository.Manifests(ctx)
	if err != nil {
		return err
	}

	blobsService := ms.repository.Blobs(ctx)

	for _, descriptor := range mnfst.References() {
		err := descriptor.Digest.Validate()
		if err != nil {
			errs = append(errs, err, distribution.ErrManifestBlobUnknown{Digest: descriptor.Digest})
			continue
		}

		switch descriptor.MediaType {
		case v1.MediaTypeImageLayer, v1.MediaTypeImageLayerGzip, v1.MediaTypeImageLayerNonDistributable, v1.MediaTypeImageLayerNonDistributableGzip: //nolint:staticcheck // Ignore SA1019 v1.MediaTypeImageLayerNonDistributable is deprecated, it is used for backwards compatibility
			allow := ms.manifestURLs.allow
			deny := ms.manifestURLs.deny
			for _, u := range descriptor.URLs {
				var pu *url.URL
				pu, err = url.Parse(u)
				if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Fragment != "" || (allow != nil && !allow.MatchString(u)) || (deny != nil && deny.MatchString(u)) {
					err = errInvalidURL
					break
				}
			}
			if err == nil {
				// check the presence if it is normal layer or
				// there is no urls for non-distributable
				if len(descriptor.URLs) == 0 ||
					(descriptor.MediaType == v1.MediaTypeImageLayer || descriptor.MediaType == v1.MediaTypeImageLayerGzip) {

					_, err = blobsService.Stat(ctx, descriptor.Digest)
				}
			}

		case v1.MediaTypeImageManifest:
			var exists bool
			exists, err = manifestService.Exists(ctx, descriptor.Digest)
			if err != nil || !exists {
				err = distribution.ErrBlobUnknown // just coerce to unknown.
			}

			if err != nil {
				dcontext.GetLogger(ms.ctx).WithError(err).Debugf("failed to ensure exists of %v in manifest service", descriptor.Digest)
			}
			fallthrough // double check the blob store.
		default:
			// check the presence
			_, err = blobsService.Stat(ctx, descriptor.Digest)
		}

		if err != nil {
			if err != distribution.ErrBlobUnknown {
				errs = append(errs, err)
			}

			// On error here, we always append unknown blob errors.
			errs = append(errs, distribution.ErrManifestBlobUnknown{Digest: descriptor.Digest})
		}
	}

	if len(errs) != 0 {
		return errs
	}

	return nil
}
