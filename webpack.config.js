var path = require('path');
var fs = require("fs");
var webpack = require("webpack");

module.exports = {
    entry: {
        'sdk.internal.bundle': ['babel-polyfill', './sdk/index.js'],
        'sdk.bundle': ['babel-polyfill', './sdk/wrapper/index.js']
    },
    devtool: 'source-map',
    output: {
        path: path.resolve(__dirname, './output/Libs'),
        filename: '[name].js',
        library: 'IonicSdk',
        libraryTarget: 'umd',
        umdNamedDefine: true
    },
    module: {
        rules: [
            {
                test: /\.js$/,
                exclude: [/node_modules/],
                use: [
                    {
                        loader: 'babel-loader',
                        options: { presets: ['es2015'] }
                    }
                ]
            }
        ]
    },
    plugins: [
        new webpack.BannerPlugin(fs.readFileSync('./LICENSE', 'utf8'))
    ]
};
