module.exports = {
    webpack: {
        configure: (webpackConfig, { env, paths }) => {
            // Find rule handling svgr (SVG -> ReactComponent) and disable SVGO option
            if (webpackConfig && webpackConfig.module && Array.isArray(webpackConfig.module.rules)) {
                for (const rule of webpackConfig.module.rules) {
                    if (rule.oneOf && Array.isArray(rule.oneOf)) {
                        for (const loaderRule of rule.oneOf) {
                            if (loaderRule && loaderRule.use) {
                                const useArr = Array.isArray(loaderRule.use) ? loaderRule.use : [loaderRule.use];
                                for (const useEntry of useArr) {
                                    const loader = useEntry && useEntry.loader;
                                    const options = useEntry && useEntry.options;
                                    if (loader && loader.includes('@svgr/webpack') && options) {
                                        // ensure svgo is disabled
                                        options.svgo = false;
                                        options.svgoConfig = {};
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return webpackConfig;
        }
    }
};