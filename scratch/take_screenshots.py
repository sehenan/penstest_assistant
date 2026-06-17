import asyncio
from playwright.async_api import async_playwright
import time
import os

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
        
        url = "http://127.0.0.1:8505"
        print(f"Connecting to {url}...")
        
        # Wait for the server to be up
        for _ in range(15):
            try:
                await page.goto(url)
                break
            except Exception:
                time.sleep(1)
        else:
            print("Server not responding.")
            return

        await page.wait_for_timeout(2000) # let animations finish
        
        output_dir = r"d:\Aptitudes\PFE\penstest_assistant\captures_pfe"
        os.makedirs(output_dir, exist_ok=True)
        
        # Dashboard
        await page.screenshot(path=f"{output_dir}\\1_dashboard.png", full_page=True)
        print("Captured dashboard")
        
        # Vulns
        await page.evaluate("nav('vulns', document.getElementById('nav-vulns'))")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=f"{output_dir}\\2_vulnerabilites.png", full_page=True)
        print("Captured vulns")
        
        # Pipeline
        await page.evaluate("nav('pipeline', document.getElementById('nav-pipeline'))")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=f"{output_dir}\\3_pipeline.png", full_page=True)
        print("Captured pipeline")
        
        # LLM
        await page.evaluate("nav('llm', document.getElementById('nav-llm'))")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=f"{output_dir}\\4_llm.png", full_page=True)
        print("Captured llm")
        
        # Reports
        await page.evaluate("nav('reports', document.getElementById('nav-reports'))")
        await page.wait_for_timeout(1000)
        await page.screenshot(path=f"{output_dir}\\5_reports.png", full_page=True)
        print("Captured reports")

        await browser.close()
        print("Screenshots saved in:", output_dir)

if __name__ == "__main__":
    asyncio.run(main())
