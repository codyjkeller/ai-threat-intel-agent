import unittest
from unittest.mock import MagicMock, patch
import sys
import os

# Ensure we can import from 'src'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.feeds import FeedAggregator, ThreatIntel

class TestFeedAggregator(unittest.TestCase):

    def test_aggregator_collects_from_all_sources(self):
        """Test that the aggregator combines results from multiple feeds."""
        
        # 1. Setup: Mock the feeds so we don't actually hit the internet
        mock_feed_1 = MagicMock()
        mock_feed_1.fetch.return_value = [
            ThreatIntel(
                source_id="MOCK_CISA", cve_id="CVE-2026-0001", 
                title="Test Vuln 1", product="Windows", 
                description="Desc", severity="CRITICAL", 
                url="http://test.com", date_added="2026-02-04"
            )
        ]

        mock_feed_2 = MagicMock()
        mock_feed_2.fetch.return_value = [
            ThreatIntel(
                source_id="MOCK_OTX", cve_id="CVE-2026-0002", 
                title="Test Vuln 2", product="Linux", 
                description="Desc", severity="HIGH", 
                url="http://test.com", date_added="2026-02-04"
            )
        ]

        # 2. Execute: Inject mocks into the Aggregator
        aggregator = FeedAggregator()
        aggregator.feeds = [mock_feed_1, mock_feed_2]
        
        results = aggregator.collect_all()

        # 3. Assert: Verify we got 2 items back
        self.assertEqual(len(results), 2)
        # Verify the data integrity
        self.assertEqual(results[0].cve_id, "CVE-2026-0001")
        self.assertEqual(results[1].source_id, "MOCK_OTX")
        print("✅ Aggregator Logic Verified")

    def test_aggregator_handles_failure(self):
        """Test that one failed feed doesn't crash the whole agent."""
        
        # Feed 1 explodes
        bad_feed = MagicMock()
        bad_feed.fetch.side_effect = Exception("API Offline")
        
        # Feed 2 works
        good_feed = MagicMock()
        good_feed.fetch.return_value = [
            ThreatIntel(
                source_id="GOOD_FEED", cve_id="CVE-2026-9999", 
                title="Survivor", product="Mac", description="...", 
                severity="LOW", url="...", date_added="..."
            )
        ]

        aggregator = FeedAggregator()
        aggregator.feeds = [bad_feed, good_feed]
        
        # Execute: Should not raise exception
        results = aggregator.collect_all()
        
        # Assert: We should still get the good data
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].cve_id, "CVE-2026-9999")
        print("✅ Error Handling Verified")

if __name__ == '__main__':
    unittest.main()
