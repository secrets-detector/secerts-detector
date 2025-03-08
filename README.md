## Analysis Modes

The Secrets Detector supports two analysis modes:

### Diff-Only Mode (Default)

In this mode, only the changes (diffs) between commits are analyzed. This is more efficient but may miss secrets that were added in previous commits.

### Full File Analysis Mode

In this mode, the complete content of all files modified in a commit is fetched and analyzed. This provides more comprehensive coverage but requires more API calls to GitHub and may be slower.

To enable Full File Analysis Mode, set the environment variable:

```bash
FULL_FILE_ANALYSIS=true
```

You can set this in your `.env` file or directly in the docker-compose command:

```bash
FULL_FILE_ANALYSIS=true docker-compose up -d
```

## Testing Modes

The application supports different testing modes for development and validation:

### Test Mode

When `TEST_MODE=true` is set, the app will skip GitHub API calls and use the data available directly in the webhook payload for analysis. This is useful for local testing without GitHub connectivity.

### Combined Testing

You can combine test modes for different testing scenarios:

```bash
# Test full file analysis with mocked GitHub calls
TEST_MODE=true FULL_FILE_ANALYSIS=true docker-compose up -d github-app
```